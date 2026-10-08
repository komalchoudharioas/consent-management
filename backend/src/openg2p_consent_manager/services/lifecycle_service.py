import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from openg2p_fastapi_common.service import BaseService
from sqlalchemy import func, select

from ..config import Settings
from ..db import async_session
from ..models import (
    ArtefactSource,
    ArtefactStatus,
    AuthContext,
    ConsentArtefact,
    ConsentRequest,
    Partner,
    RequestStatus,
)
from .otp_service import OtpError, OtpService
from .partner_service import PartnerService
from .receipt_service import ReceiptService

_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)


class LifecycleError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


class LifecycleService(BaseService):
    """Origination flow: request → authenticate → approve / deny."""

    def __init__(self, name="", **kwargs):
        super().__init__(name, **kwargs)
        self.partners = PartnerService.get_component()
        self.receipts = ReceiptService.get_component()

    @property
    def otp(self) -> OtpService:
        """Resolved on use, not in __init__: this service is constructed before
        OtpService is registered, so binding it early binds None."""
        return OtpService.get_component()

    async def create_request(self, data) -> ConsentRequest:
        policy = await self.partners.get_policy(data.partner_id)
        if policy is None:
            raise LifecycleError(404, "partner or policy not found")

        partner = await self.partners.get_partner(data.partner_id)
        if partner is None:
            raise LifecycleError(404, "partner not found")

        # Reject up front anything the policy can never satisfy.
        if not set(data.requested_scopes).issubset(set(policy.allowed_data_scopes or [])):
            raise LifecycleError(422, "scope_exceeds_policy")

        validity = data.validity or {}
        async with async_session()() as session:
            req = ConsentRequest(
                subject_id_type=data.subject_id.type,
                subject_id_value=data.subject_id.value,
                controller_id=partner.controller_id,
                partner_id=data.partner_id,
                purpose=data.purpose,
                requested_scopes=data.requested_scopes,
                valid_from=validity.get("valid_from"),
                valid_until=validity.get("valid_until"),
                status=RequestStatus.pending.value,
            )
            session.add(req)
            await session.commit()
            await session.refresh(req)
            return req

    async def list_subject_requests(
        self, subject_id_type: str, subject_id_value: str,
        status: Optional[str] = None, page: int = 1, size: int = 20,
    ) -> dict:
        """The subject's own consent requests, newest first.

        Scoped by subject on the query itself, not filtered afterwards: a
        pending request names the partner, the purpose and every scope being
        asked for, so returning someone else's row would disclose that they are
        being asked at all.
        """
        async with async_session()() as session:
            base = select(ConsentRequest).where(
                ConsentRequest.subject_id_type == subject_id_type,
                ConsentRequest.subject_id_value == subject_id_value,
            )
            if status:
                base = base.where(ConsentRequest.status == status)
            total = int((await session.execute(
                select(func.count()).select_from(base.subquery()))).scalar() or 0)
            rows = (await session.execute(
                base.order_by(ConsentRequest.created_at.desc())
                .offset((page - 1) * size).limit(size)
            )).scalars().all()
            return {"items": rows, "total": total, "page": page, "size": size,
                    "pages": max(1, (total + size - 1) // size)}

    async def get_request(self, request_id: str) -> Optional[ConsentRequest]:
        async with async_session()() as session:
            return await session.get(ConsentRequest, request_id)

    async def authenticate(self, request_id: str, id_token: str) -> AuthContext:
        async with async_session()() as session:
            req = await session.get(ConsentRequest, request_id)
            if req is None:
                raise LifecycleError(404, "consent request not found")
            if req.status != RequestStatus.pending.value:
                raise LifecycleError(409, f"request is '{req.status}'")

            claims, validated = self._decode_id_token(id_token)
            # Subject identity in the token must match the request's subject.
            sub = claims.get("subject_id_value") or claims.get("sub")
            if sub and sub != req.subject_id_value:
                raise LifecycleError(403, "token subject does not match request")

            ctx = AuthContext(
                consent_request_id=request_id,
                auth_provider=claims.get("iss"),
                auth_method=(claims.get("amr") or [None])[0]
                if isinstance(claims.get("amr"), list)
                else claims.get("amr"),
                auth_timestamp=datetime.now(timezone.utc),
                issuer=claims.get("iss"),
                id_token_hash=hashlib.sha256(id_token.encode("utf-8")).hexdigest(),
                token_validated=validated,
                verified_claims=claims,
            )
            session.add(ctx)
            await session.commit()
            await session.refresh(ctx)
            return ctx

    # ── OTP authentication ───────────────────────────────────────────────────
    # The subject authenticates where they grant. An OTP here is an alternative
    # to `authenticate(id_token)`, not an extra step after approval: both end in
    # the same AuthContext, and `approve` will not proceed without one.

    async def issue_otp(self, request_id: str) -> ConsentRequest:
        """Send the subject a one-time code for this consent request."""
        async with async_session()() as session:
            req = await session.get(ConsentRequest, request_id)
            if req is None:
                raise LifecycleError(404, "consent request not found")
            if req.status != RequestStatus.pending.value:
                raise LifecycleError(409, f"request is '{req.status}'")

            # Re-issuing resets the attempt count: the old code is dead, so
            # carrying its failures forward would punish the wrong code.
            req.otp_attempts = 0
            req.otp_verified_at = None
            await self.otp.issue(req, req.subject_id_value)
            await session.commit()
            await session.refresh(req)
            return req

    async def verify_otp(self, request_id: str, code: str) -> AuthContext:
        """Check the code and record it as the subject's authentication."""
        async with async_session()() as session:
            req = await session.get(ConsentRequest, request_id)
            if req is None:
                raise LifecycleError(404, "consent request not found")
            if req.status != RequestStatus.pending.value:
                raise LifecycleError(409, f"request is '{req.status}'")
            if not req.otp_hash:
                raise LifecycleError(409, "no OTP has been issued for this request")

            try:
                await self.otp.verify(req, code)
            except OtpError as exc:
                await session.commit()   # persist the attempt count either way
                raise LifecycleError(exc.status, exc.reason) from exc

            ctx = AuthContext(
                consent_request_id=request_id,
                auth_provider=req.otp_provider or "otp",
                auth_method="otp",
                auth_timestamp=req.otp_verified_at or datetime.now(timezone.utc),
                issuer=req.otp_provider or "otp",
                # There is no ID token in this path. The column is not nullable,
                # so it carries a hash that identifies the act without implying a
                # token existed; token_validated stays False for the same reason.
                id_token_hash=hashlib.sha256(
                    ("otp:" + request_id).encode("utf-8")).hexdigest(),
                token_validated=False,
                verified_claims={
                    "auth_method": "otp",
                    "otp_channel": req.otp_channel,
                    "otp_provider": req.otp_provider,
                    "otp_reference": req.otp_reference,
                    "consent_request_id": request_id,
                    "subject_id_value": req.subject_id_value,
                },
            )
            session.add(ctx)
            await session.commit()
            await session.refresh(ctx)
            _logger.info("Consent request %s: subject authenticated by OTP", request_id)
            return ctx

    async def approve(self, request_id: str, granted_scopes: list) -> ConsentArtefact:
        async with async_session()() as session:
            req = await session.get(ConsentRequest, request_id)
            if req is None:
                raise LifecycleError(404, "consent request not found")
            if req.status != RequestStatus.pending.value:
                raise LifecycleError(409, f"request is '{req.status}'")

            ctx = await self._latest_auth_context(session, request_id)
            if ctx is None:
                raise LifecycleError(412, "authentication required before approval")

            # A policy may demand a specific proof. Checking it here rather than
            # in the UI is the point: the screen can be bypassed, this cannot.
            required = (await self.partners.get_policy(req.partner_id))
            required = getattr(required, "required_auth_method", None)
            if required and (ctx.auth_method or "") != required:
                raise LifecycleError(
                    412,
                    "this partner requires '%s' authentication; the subject "
                    "authenticated with '%s'" % (required, ctx.auth_method or "none"),
                )

            if not set(granted_scopes).issubset(set(req.requested_scopes or [])):
                raise LifecycleError(400, "granted scopes exceed requested scopes")

            policy = await self.partners.get_policy(req.partner_id)
            allowed = set(policy.allowed_data_scopes or []) if policy else set()
            effective = sorted(set(granted_scopes) & allowed)
            if not effective:
                raise LifecycleError(400, "no granted scope permitted by policy")

            partner = await session.get(Partner, req.partner_id)
            now = datetime.now(timezone.utc)
            valid_from = req.valid_from or now
            valid_until = req.valid_until or (now + timedelta(days=365))

            artefact = ConsentArtefact(
                subject_id_type=req.subject_id_type,
                subject_id_value=req.subject_id_value,
                controller_id=req.controller_id,
                partner_id=req.partner_id,
                purpose=req.purpose,
                data_scopes=req.requested_scopes,
                effective_data_scopes=effective,
                fetch_type=policy.fetch_type if policy else "oneshot",
                valid_from=valid_from,
                valid_until=valid_until,
                source=ArtefactSource.originated.value,
                policy_version=policy.version if policy else None,
                auth_context_id=ctx.id,
                status=ArtefactStatus.active.value,
            )
            receipt = self.receipts.build_receipt(artefact, partner)
            req.status = RequestStatus.approved.value
            session.add(artefact)
            session.add(receipt)
            await session.commit()
            await session.refresh(artefact)
        return artefact

    async def deny(self, request_id: str, reason: Optional[str]) -> ConsentRequest:
        async with async_session()() as session:
            req = await session.get(ConsentRequest, request_id)
            if req is None:
                raise LifecycleError(404, "consent request not found")
            if req.status != RequestStatus.pending.value:
                raise LifecycleError(409, f"request is '{req.status}'")
            req.status = RequestStatus.denied.value
            await session.commit()
            await session.refresh(req)
            return req

    # ── helpers ──────────────────────────────────────────────────────────────

    async def _latest_auth_context(self, session, request_id: str) -> Optional[AuthContext]:
        result = await session.execute(
            select(AuthContext)
            .where(AuthContext.consent_request_id == request_id)
            .order_by(AuthContext.created_at.desc())
        )
        return result.scalars().first()

    def _decode_id_token(self, id_token: str) -> tuple[dict, bool]:
        """Return (claims, validated). Verifies against the IdP JWKS if configured."""
        if _config.oidc_jwks_url:
            try:
                jwk_client = jwt.PyJWKClient(_config.oidc_jwks_url)
                signing_key = jwk_client.get_signing_key_from_jwt(id_token)
                claims = jwt.decode(
                    id_token,
                    signing_key.key,
                    algorithms=["RS256", "ES256", "EdDSA"],
                    audience=_config.oidc_audience or None,
                    issuer=_config.oidc_issuer or None,
                    options={"verify_aud": bool(_config.oidc_audience)},
                )
                return claims, True
            except Exception as exc:
                raise LifecycleError(401, f"ID token validation failed: {exc}")
        _logger.warning(
            "oidc_jwks_url not configured — decoding ID token WITHOUT signature "
            "verification (dev only)."
        )
        try:
            claims = jwt.decode(id_token, options={"verify_signature": False})
        except Exception as exc:
            # The verified branch above turns a bad token into a 401; this one
            # used to let PyJWT's DecodeError escape as an unhandled 500, so a
            # malformed token read as "the server broke" rather than "your
            # token is not a token".
            raise LifecycleError(401, f"ID token could not be decoded: {exc}")
        return claims, False
