import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from openg2p_fastapi_common.service import BaseService
from openg2p_fastapi_common.utils.crypto import build_crypto_helper
from sqlalchemy import select

from ..config import Settings
from ..db import async_session
from ..models import (
    ArtefactSource,
    ArtefactStatus,
    ConsentArtefact,
    DecisionLog,
)
from ..schemas.common import ReasonCode
from ..schemas.verification import ConsentObject, Decision, ValidateRequest
from ..utils.canonical import b64url_decode, sha256_hex
from .partner_service import PartnerService
from .policy_service import PolicyService
from .receipt_service import ReceiptService

_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class VerificationService(BaseService):
    """The PDP hot path: verify an embedded consent object → decision."""

    def __init__(self, name="", **kwargs):
        super().__init__(name, **kwargs)
        self.partners = PartnerService.get_component()
        # Partner consent-JWS verification via the shared fastapi-common crypto
        # helper (partner-mgmt backend fetches keys from Partner Management).
        self.crypto_helper = build_crypto_helper(backend=_config.crypto_backend)
        self.policy = PolicyService.get_component()
        self.receipts = ReceiptService.get_component()

    @staticmethod
    def _decode_jws(jws: str) -> tuple[dict, dict]:
        """Return ``(claims, protected_header)`` from a compact JWS WITHOUT
        verifying — used to identify the partner and read alg/kid before the
        signature is checked. A permit is never issued on unverified claims."""
        parts = jws.split(".")
        if len(parts) != 3:
            raise ValueError("consent_jws is not a compact JWS (expected header.payload.signature)")
        protected_header = json.loads(b64url_decode(parts[0]))
        claims = json.loads(b64url_decode(parts[1]))
        return claims, protected_header

    async def validate(self, parsed: ValidateRequest) -> Decision:
        now = datetime.now(timezone.utc)
        jws = parsed.consent_jws
        # The JWS string is itself canonical/immutable, so hash it directly.
        ctx_hash = sha256_hex(jws.encode("utf-8"))

        # Recover the claims from the JWS payload (unverified) so we can identify
        # the partner and evaluate policy. The signature is verified below,
        # before any permit is issued.
        try:
            claims, jws_header = self._decode_jws(jws)
            obj = ConsentObject(**claims)
        except Exception as exc:
            _logger.info("Malformed consent JWS: %s", exc)
            return await self._deny(
                ReasonCode.malformed_object, "consent JWS could not be decoded",
                now, ctx_hash,
            )

        # Idempotency: the same object (jti) returns its existing decision.
        existing = await self._existing_artefact(obj.jti)
        if existing is not None:
            return self._decision_from_artefact(existing, now)

        # 2. Known party — partner + policy (cached).
        material = await self.partners.get_verification_material(obj.aud)
        if material is None:
            return await self._deny(
                ReasonCode.unknown_partner, "partner not onboarded or suspended",
                now, ctx_hash, jti=obj.jti,
            )
        partner = material["partner"]
        policy = material["policy"]
        policy_version = policy.version if policy else None

        # 3. Signature — verify the consent JWS against the partner's key from
        # Partner Management. The shared helper reads the kid from the JWS header,
        # fetches the key for the partner's PM reference (partner_mgmt_id, falling
        # back to audience), enforces algorithm safety, and verifies.
        reference_id = partner.partner_mgmt_id or partner.audience
        alg = jws_header.get("alg")
        if policy and policy.allowed_signing_algs and alg not in policy.allowed_signing_algs:
            return await self._deny(
                ReasonCode.signature_invalid, "signing algorithm not permitted",
                now, ctx_hash, partner_id=partner.id, jti=obj.jti,
                policy_version=policy_version,
            )
        try:
            verified = await self.crypto_helper.verify_jwt(jws, km_ref_id=reference_id)
        except Exception as exc:
            _logger.warning("Consent JWS verification error: %s", exc)
            verified = False
        if not verified:
            return await self._deny(
                ReasonCode.signature_invalid,
                "signature did not verify (or no verifying key from partner management)",
                now, ctx_hash, partner_id=partner.id, jti=obj.jti,
                policy_version=policy_version,
            )

        # 10. Replay / freshness — issued_at within the configured window.
        issued_at = _aware(obj.issued_at)
        skew = timedelta(seconds=_config.replay_freshness_window_sec)
        if abs((now - issued_at).total_seconds()) > skew.total_seconds():
            return await self._deny(
                ReasonCode.replay, "issued_at outside freshness window",
                now, ctx_hash, partner_id=partner.id, jti=obj.jti,
                policy_version=policy_version,
            )

        # 4–8. Policy evaluation (audience, subject, purpose, scope, validity).
        result = self.policy.evaluate(obj, material, parsed.request_context)
        if not result.permit:
            return await self._deny(
                result.reason, result.detail, now, ctx_hash,
                partner_id=partner.id, jti=obj.jti, policy_version=result.policy_version,
            )

        # 9. Subject grant (gap B8) — if the subject granted a consent to this
        # partner through the origination flow, that grant is AUTHORITATIVE: it
        # narrows what the partner's self-asserted object can obtain, and makes
        # the subject's revocation actually bite.
        grant = None
        basis = await self._lawful_basis(partner.id)
        if _config.subject_consent_enabled:
            grant = await self._active_subject_grant(partner.id, obj.subject_id)
            if grant is None:
                # A partner operating on the controller's own lawful basis is
                # never sent to look for a grant. Reaching here means steps 1-8
                # already passed, so what is being skipped is ONLY the subject's
                # say - the signature, the replay window and the policy ceiling
                # in result.effective_scopes all still bind, and that ceiling is
                # now the whole of what this partner can obtain.
                if basis != "consent":
                    _logger.info(
                        "Partner %s: no subject grant sought - lawful_basis=%s. "
                        "Releasing %d scope(s) on the policy ceiling alone.",
                        partner.id, basis, len(result.effective_scopes or []))
                elif _config.subject_consent_required:
                    return await self._deny(
                        ReasonCode.no_subject_consent,
                        "the subject has not granted an active consent to this partner",
                        now, ctx_hash, partner_id=partner.id, jti=obj.jti,
                        policy_version=result.policy_version,
                    )
            else:
                granted = set(grant.effective_data_scopes or [])
                narrowed = sorted(set(result.effective_scopes) & granted)
                if not narrowed:
                    return await self._deny(
                        ReasonCode.scope_exceeds_policy,
                        "no requested scope was granted by the subject",
                        now, ctx_hash, partner_id=partner.id, jti=obj.jti,
                        policy_version=result.policy_version,
                    )
                result.effective_scopes = narrowed

        # Permit — mint canonical artefact + signed receipt + decision log.
        return await self._permit(
            obj, partner, result, now, ctx_hash, grant=grant, basis=basis
        )

    async def _lawful_basis(self, partner_id: str) -> str:
        """Why this partner may hold the data — "consent" unless stated.

        Anything unrecognised, and a partner with no active policy at all, reads
        as "consent": the strict answer is the safe one, and a basis that stops
        being understood must not become a way past the subject.
        """
        policy = await self.partners.get_policy(partner_id)
        basis = getattr(policy, "lawful_basis", None) if policy else None
        return basis if basis in ("consent", "legitimate_interest") else "consent"

    async def _active_subject_grant(self, partner_id: str, subject_id):
        """The subject's own granted consent (origination flow) for this partner.

        Returns the newest ACTIVE, unexpired originated artefact matching the
        partner and the subject identified in the partner's consent object, or
        None. A revoked or expired grant returns None, so revocation takes
        effect on the next fetch.
        """
        now = datetime.now(timezone.utc)
        async with async_session()() as session:
            rows = await session.execute(
                select(ConsentArtefact)
                .where(
                    ConsentArtefact.partner_id == partner_id,
                    ConsentArtefact.source == ArtefactSource.originated.value,
                    ConsentArtefact.status == ArtefactStatus.active.value,
                    ConsentArtefact.subject_id_type == subject_id.type,
                    ConsentArtefact.subject_id_value == subject_id.value,
                )
                .order_by(ConsentArtefact.created_at.desc())
            )
            for artefact in rows.scalars().all():
                if _aware(artefact.valid_until) > now:
                    return artefact
        return None

    # ── helpers ──────────────────────────────────────────────────────────────

    async def list_decisions(
        self,
        partner_id: Optional[str] = None,
        decision: Optional[str] = None,
        limit: int = 50,
    ) -> list:
        """Recent validation decisions (append-only log), newest first — for the
        admin console's operational/audit status view."""
        async with async_session()() as session:
            query = select(DecisionLog)
            if partner_id:
                query = query.where(DecisionLog.partner_id == partner_id)
            if decision:
                query = query.where(DecisionLog.decision == decision)
            query = query.order_by(DecisionLog.created_at.desc()).limit(min(limit, 200))
            result = await session.execute(query)
            return list(result.scalars().all())

    async def _existing_artefact(self, jti: str) -> Optional[ConsentArtefact]:
        async with async_session()() as session:
            result = await session.execute(
                select(ConsentArtefact).where(ConsentArtefact.object_jti == jti)
            )
            return result.scalars().first()

    def _decision_from_artefact(self, artefact: ConsentArtefact, now: datetime) -> Decision:
        from ..schemas.common import SubjectId

        status = artefact.status
        if status == ArtefactStatus.active.value and _aware(artefact.valid_until) < now:
            status = ArtefactStatus.expired.value
        if status == ArtefactStatus.revoked.value:
            return Decision(
                decision="deny", reason_code=ReasonCode.revoked,
                detail="consent revoked", evaluated_at=now,
            )
        if status == ArtefactStatus.expired.value:
            return Decision(
                decision="deny", reason_code=ReasonCode.expired,
                detail="consent expired", evaluated_at=now,
            )
        return Decision(
            decision="permit", reason_code=ReasonCode.ok,
            consent_id=artefact.id,
            subject_id=SubjectId(type=artefact.subject_id_type, value=artefact.subject_id_value),
            effective_data_scopes=artefact.effective_data_scopes,
            valid_until=artefact.valid_until, policy_version=artefact.policy_version,
            partner_id=artefact.partner_id,
            evaluated_at=now,
        )

    async def _permit(self, obj, partner, result, now, ctx_hash, grant=None,
                      basis: str = "consent") -> Decision:
        from ..schemas.common import SubjectId

        artefact = ConsentArtefact(
            subject_id_type=obj.subject_id.type,
            subject_id_value=obj.subject_id.value,
            controller_id=partner.controller_id,
            partner_id=partner.id,
            purpose=obj.purpose,
            data_scopes=obj.data_scopes,
            effective_data_scopes=result.effective_scopes,
            fetch_type=obj.fetch_type,
            valid_from=_aware(obj.validity.valid_from),
            valid_until=_aware(obj.validity.valid_until),
            source=ArtefactSource.embedded.value,
            policy_version=result.policy_version,
            object_jti=obj.jti,
            # Gap B8: when the subject granted this consent, carry their auth
            # context onto the fetch artefact. This is the link that was missing
            # between the two flows.
            auth_context_id=grant.auth_context_id if grant is not None else None,
            status=ArtefactStatus.active.value,
        )
        receipt = self.receipts.build_receipt(artefact, partner)

        async with async_session()() as session:
            session.add(artefact)
            session.add(receipt)
            session.add(
                DecisionLog(
                    partner_id=partner.id, consent_id=artefact.id, object_jti=obj.jti,
                    decision="permit", reason_code=ReasonCode.ok.value,
                    policy_version=result.policy_version, request_ctx_hash=ctx_hash,
                )
            )
            await session.commit()
            await session.refresh(artefact)
            await session.refresh(receipt)

        return Decision(
            decision="permit", reason_code=ReasonCode.ok,
            consent_id=artefact.id, receipt_id=receipt.id,
            subject_id=SubjectId(type=obj.subject_id.type, value=obj.subject_id.value),
            effective_data_scopes=result.effective_scopes,
            valid_until=artefact.valid_until, policy_version=result.policy_version,
            lawful_basis=basis,
            partner_id=partner.id,
            partner_audience=partner.audience,
            evaluated_at=now,
        )

    async def _deny(
        self, reason: ReasonCode, detail: Optional[str], now, ctx_hash,
        partner_id: Optional[str] = None, jti: Optional[str] = None,
        policy_version: Optional[int] = None,
    ) -> Decision:
        async with async_session()() as session:
            session.add(
                DecisionLog(
                    partner_id=partner_id, object_jti=jti, decision="deny",
                    reason_code=reason.value, detail=detail,
                    policy_version=policy_version, request_ctx_hash=ctx_hash,
                )
            )
            await session.commit()
        return Decision(
            decision="deny", reason_code=reason, detail=detail, evaluated_at=now,
        )
