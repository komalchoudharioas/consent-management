"""What the CM does on behalf of the Aggregation Layer.

The Aggregation Layer is a separate service with its own database. Two things it
used to do by writing and reading CM tables directly now happen here, behind
service-role APIs (see ``controllers/aggregation_layer_controller.py``):

``record_grants``  (POST /consent/v1/grants)
    The subject authenticated (OTP), or their standing consent was enough, or the
    partner is under legitimate interest. Whichever it was is written down as one
    AuthContext plus one originated grant per registry binding the aggregator will
    spend. Without these the aggregator holds a policy ceiling but no subject
    grant, and B8 denies it at every registry.

``granted_scopes``  (GET /consent/v1/consent-requests/{id}/granted-scopes)
    After the subject approved a consent request the aggregator raised, what did
    they actually grant, and how did they authenticate.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from openg2p_fastapi_common.service import BaseService
from sqlalchemy import select

from ..config import Settings
from ..db import async_session
from ..models import (
    ArtefactSource,
    ArtefactStatus,
    AuthContext,
    ConsentArtefact,
    ConsentRequest,
    Partner,
)
from ..utils import sha256_hex

_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class AggregationLayerService(BaseService):
    def __init__(self, name="", **kwargs):
        super().__init__(name if name else "AggregationLayerService", **kwargs)

    # ── POST /consent/v1/grants ─────────────────────────────────────────────

    async def record_grants(self, data) -> Dict[str, Any]:
        """One AuthContext for the act, one originated grant per binding.

        ``auth_method`` is what the subject actually did: "otp", "consent" (the
        policy asked for no code; the standing grant is the authority) or
        "none" (legitimate interest). The AuthContext is written even when every
        grant is reused - the subject did authenticate, and that act belongs in
        the trail.
        """
        now = datetime.now(timezone.utc)
        valid_until = _aware(data.valid_until)
        purpose = data.purpose or {}

        async with async_session()() as session:
            ctx = AuthContext(
                # The aggregation id, which is what lets My consents group the
                # per-registry grants under the consent that caused them.
                consent_request_id=data.aggregation_id,
                auth_provider=data.issuer,
                auth_method=data.auth_method,
                auth_timestamp=_aware(data.auth_timestamp) if data.auth_timestamp else now,
                issuer=data.issuer,
                # No ID token exists here. The column is NOT NULL, so it carries a
                # hash that identifies the act without implying a token existed;
                # token_validated stays False for the same reason.
                id_token_hash=sha256_hex(
                    (data.auth_method + ":" + data.aggregation_id).encode("utf-8")),
                token_validated=False,
                verified_claims={
                    "auth_method": data.auth_method,
                    "lawful_basis": data.lawful_basis,
                    "otp_channel": data.otp_channel,
                    "aggregation_id": data.aggregation_id,
                    "subject_id_value": data.subject_id.value,
                    # Read by ConsentService._classify to group these grants
                    # under the consent they came from.
                    "consent_request_id": data.consent_request_id,
                    "root_consent_id": data.root_consent_id,
                },
            )
            session.add(ctx)

            minted: List[str] = []
            reused: List[str] = []
            skipped: List[Dict[str, str]] = []
            for binding in data.bindings:
                partner = await self._binding_for(session, binding.audience)
                if partner is None:
                    skipped.append({"registry": binding.registry,
                                    "reason": "unknown_audience"})
                    continue
                existing = await self._reusable_grant(
                    session, partner.id, data, binding.scopes, purpose, now)
                if existing is not None:
                    reused.append(binding.registry)
                    continue
                session.add(ConsentArtefact(
                    subject_id_type=data.subject_id.type,
                    subject_id_value=data.subject_id.value,
                    controller_id=partner.controller_id,
                    partner_id=partner.id,
                    purpose=purpose,
                    data_scopes=binding.scopes,
                    effective_data_scopes=binding.scopes,
                    fetch_type="oneshot",
                    valid_from=now,
                    valid_until=valid_until,
                    source=ArtefactSource.originated.value,
                    auth_context_id=ctx.id,
                    status=ArtefactStatus.active.value,
                ))
                minted.append(binding.registry)
            await session.commit()

        _logger.info("Aggregation %s: %s-backed grants minted for %s, reused for %s, "
                     "skipped %s", data.aggregation_id, data.auth_method,
                     minted, reused, [s["registry"] for s in skipped])
        return {"auth_context_id": ctx.id, "minted": minted,
                "reused": reused, "skipped": skipped}

    @staticmethod
    async def _binding_for(session, audience: Optional[str]) -> Optional[Partner]:
        if not audience:
            return None
        result = await session.execute(
            select(Partner).where(Partner.audience == audience)
            .order_by(Partner.created_at.desc()))
        return result.scalars().first()

    @staticmethod
    async def _reusable_grant(session, partner_id: str, data, scopes: List[str],
                              purpose: Dict[str, Any],
                              now: datetime) -> Optional[ConsentArtefact]:
        """The grant B8 would pick for this binding, if it already says this.

        Only the NEWEST live grant is a candidate, because that is the one the
        registry's PDP reads: skipping the mint while an older grant matched
        would leave a different, newer one deciding the fetch.

        Reused only on an exact match, never a superset - a broader grant would
        make the registry release blocks this request did not ask for - and only
        when it came from the same issuer with the same method and lawful basis,
        or the audit trail would claim an OTP stood behind a fetch that had none.
        """
        result = await session.execute(
            select(ConsentArtefact)
            .where(ConsentArtefact.partner_id == partner_id,
                   ConsentArtefact.subject_id_type == data.subject_id.type,
                   ConsentArtefact.subject_id_value == data.subject_id.value,
                   ConsentArtefact.source == ArtefactSource.originated.value,
                   ConsentArtefact.status == ArtefactStatus.active.value)
            .order_by(ConsentArtefact.created_at.desc())
        )
        candidate, until = None, None
        for artefact in result.scalars().all():
            until = _aware(artefact.valid_until)
            if until > now:
                candidate = artefact
                break
        if candidate is None or not candidate.auth_context_id:
            return None
        if (until - now).total_seconds() < data.reuse_min_remaining_sec:
            return None
        if sorted(candidate.effective_data_scopes or []) != sorted(scopes):
            return None
        if (candidate.purpose or {}) != purpose:
            return None
        ctx = await session.get(AuthContext, candidate.auth_context_id)
        if ctx is None or ctx.auth_provider != data.issuer:
            return None
        claims = ctx.verified_claims or {}
        if (ctx.auth_method != data.auth_method
                or claims.get("lawful_basis", "consent") != data.lawful_basis):
            return None
        return candidate

    # ── GET /consent/v1/consent-requests/{id}/granted-scopes ────────────────

    async def granted_scopes(self, request_id: str) -> Optional[Dict[str, Any]]:
        """What an approved request granted, and how the subject authenticated.

        The grant is found through its AuthContext (``consent_request_id`` =
        this request), so it is the artefact THIS approval minted - not merely
        the newest one for the partner and subject, which a later, unrelated
        approval could have replaced.
        """
        async with async_session()() as session:
            req = await session.get(ConsentRequest, request_id)
            if req is None:
                return None
            ctx_ids = list((await session.execute(
                select(AuthContext.id)
                .where(AuthContext.consent_request_id == request_id))).scalars().all())
            artefact = None
            if ctx_ids:
                artefact = (await session.execute(
                    select(ConsentArtefact)
                    .where(ConsentArtefact.auth_context_id.in_(ctx_ids),
                           ConsentArtefact.source == ArtefactSource.originated.value)
                    .order_by(ConsentArtefact.created_at.desc()))).scalars().first()

        live = (artefact is not None
                and artefact.status == ArtefactStatus.active.value
                and _aware(artefact.valid_until) > datetime.now(timezone.utc))
        return {
            "request_id": req.id,
            "status": req.status,
            "partner_id": req.partner_id,
            "subject_id": {"type": req.subject_id_type, "value": req.subject_id_value},
            # Empty when not approved, or when the grant was since withdrawn or
            # expired - the aggregator then releases nothing.
            "granted_scopes": list(artefact.effective_data_scopes or []) if live else [],
            "consent_id": artefact.id if artefact is not None else None,
            "otp_verified_at": (req.otp_verified_at.isoformat()
                                if req.otp_verified_at else None),
            "otp_channel": req.otp_channel,
            "otp_provider": req.otp_provider,
        }
