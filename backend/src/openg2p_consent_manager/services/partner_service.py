import logging
from datetime import datetime, timezone
from typing import Optional

from openg2p_fastapi_common.service import BaseService
from sqlalchemy import func, select

from ..config import Settings
from ..db import async_session
from ..models import (
    Partner,
    PartnerPolicy,
    PartnerStatus,
    PolicyStatus,
)
from ..utils import TTLCache, iso_duration_to_timedelta

_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)


class PartnerService(BaseService):
    """Partner *policy bindings* (admin) plus the cached lookups the hot path
    needs. Partner identity + keys live in Partner Management; a row here binds a
    PM partner to a controller and a versioned data-share policy."""

    def __init__(self, name="", **kwargs):
        super().__init__(name, **kwargs)
        self._cache = TTLCache(_config.partner_cache_ttl_sec)

    # ── Admin: bindings ──────────────────────────────────────────────────────

    async def create_partner(self, data) -> Partner:
        # A binding is created active. Partner *identity* onboarding/approval is
        # Partner Management's concern; CM only gates data-share POLICY widening
        # (see upsert_policy). A binding with no policy simply denies everything
        # until a policy is set.
        async with async_session()() as session:
            partner = Partner(
                name=data.name,
                audience=data.audience,
                controller_id=data.controller_id,
                partner_mgmt_id=data.partner_mgmt_id,
                status=PartnerStatus.active.value,
            )
            session.add(partner)
            await session.commit()
            await session.refresh(partner)
            return partner

    async def get_partner(self, partner_id: str) -> Optional[Partner]:
        async with async_session()() as session:
            return await session.get(Partner, partner_id)

    async def get_partner_by_audience(self, audience: str) -> Optional[Partner]:
        """The binding for an audience (newest if, unusually, there are several)."""
        async with async_session()() as session:
            result = await session.execute(
                select(Partner).where(Partner.audience == audience)
                .order_by(Partner.created_at.desc()))
            return result.scalars().first()

    async def list_partners(
        self, controller_id: Optional[str] = None, status: Optional[str] = None
    ) -> list:
        """List partners for the admin console, newest first. Optional filters by
        controller (registry) and lifecycle status."""
        async with async_session()() as session:
            query = select(Partner)
            if controller_id:
                query = query.where(Partner.controller_id == controller_id)
            if status:
                query = query.where(Partner.status == status)
            query = query.order_by(Partner.created_at.desc())
            result = await session.execute(query)
            return list(result.scalars().all())

    async def update_partner(self, partner_id: str, data) -> Optional[Partner]:
        async with async_session()() as session:
            partner = await session.get(Partner, partner_id)
            if partner is None:
                return None
            for field in ("name", "status", "partner_mgmt_id"):
                value = getattr(data, field, None)
                if value is not None:
                    setattr(partner, field, value)
            await session.commit()
            await session.refresh(partner)
        self._invalidate(partner.audience)
        return partner

    # ── Admin: policy (versioned) ────────────────────────────────────────────

    async def upsert_policy(self, partner_id: str, data) -> Optional[PartnerPolicy]:
        """Create a new data-share policy version.

        If AWE approval is enabled AND the change *widens* access relative to the
        current active policy (or is the first policy), the new version is created
        ``pending`` and does NOT supersede the active one — the caller submits it
        to AWE and it only goes active on approval. A non-widening change (or AWE
        disabled) activates immediately, superseding the prior active version.
        """
        async with async_session()() as session:
            partner = await session.get(Partner, partner_id)
            if partner is None:
                return None

            result = await session.execute(
                select(PartnerPolicy)
                .where(PartnerPolicy.partner_id == partner_id)
                .order_by(PartnerPolicy.version.desc())
            )
            existing = list(result.scalars().all())
            active = next(
                (p for p in existing if p.status == PolicyStatus.active.value), None
            )
            next_version = (existing[0].version + 1) if existing else 1

            gated = _config.awe_enabled and self._is_widening(data, active)

            if gated:
                status = PolicyStatus.pending.value
                effective_from = None
                # Do NOT supersede the active policy — it stays in force until
                # this pending version is approved.
            else:
                status = PolicyStatus.active.value
                effective_from = datetime.now(timezone.utc)
                if active is not None:
                    active.status = PolicyStatus.superseded.value

            policy = PartnerPolicy(
                partner_id=partner_id,
                version=next_version,
                status=status,
                allowed_data_scopes=data.allowed_data_scopes,
                allowed_purposes=data.allowed_purposes,
                allowed_subject_id_types=data.allowed_subject_id_types,
                allowed_signing_algs=data.allowed_signing_algs,
                max_validity_duration=data.max_validity_duration,
                fetch_type=data.fetch_type,
                max_fetch_frequency=data.max_fetch_frequency,
                data_life=data.data_life,
                required_auth_method=data.required_auth_method,
                lawful_basis=getattr(data, "lawful_basis", "consent") or "consent",
                effective_from=effective_from,
            )
            session.add(policy)
            await session.commit()
            await session.refresh(policy)
            audience = partner.audience

        if not gated:
            self._invalidate(audience)  # active policy changed
        return policy

    async def set_policy_awe_request_id(self, policy_id: str, awe_request_id: str) -> None:
        async with async_session()() as session:
            policy = await session.get(PartnerPolicy, policy_id)
            if policy is not None:
                policy.awe_request_id = awe_request_id
                await session.commit()

    async def apply_policy_decision(
        self, awe_request_id: str, artifact_id: str, approved: bool
    ) -> bool:
        """Apply a terminal AWE decision to a pending policy version. On approve,
        activate it and supersede the prior active version for that partner; on
        reject, mark it rejected. Matches by AWE request id, else artifact id
        (== policy id). Returns False if no pending policy correlates."""
        async with async_session()() as session:
            policy = None
            if awe_request_id:
                res = await session.execute(
                    select(PartnerPolicy).where(
                        PartnerPolicy.awe_request_id == awe_request_id
                    )
                )
                policy = res.scalars().first()
            if policy is None and artifact_id:
                policy = await session.get(PartnerPolicy, artifact_id)
            if policy is None:
                return False
            # Idempotent: a re-delivered webhook for an already-decided version.
            if policy.status != PolicyStatus.pending.value:
                partner = await session.get(Partner, policy.partner_id)
                if partner:
                    self._invalidate(partner.audience)
                return True

            if approved:
                # Supersede whatever is currently active for this partner.
                res = await session.execute(
                    select(PartnerPolicy).where(
                        PartnerPolicy.partner_id == policy.partner_id,
                        PartnerPolicy.status == PolicyStatus.active.value,
                    )
                )
                for old in res.scalars().all():
                    old.status = PolicyStatus.superseded.value
                policy.status = PolicyStatus.active.value
                policy.effective_from = datetime.now(timezone.utc)
            else:
                policy.status = PolicyStatus.rejected.value

            partner = await session.get(Partner, policy.partner_id)
            audience = partner.audience if partner else None
            await session.commit()
        if audience:
            self._invalidate(audience)
        return True

    async def list_policies(self, partner_id: str) -> Optional[list]:
        """All policy versions for a binding, newest first. None if no binding."""
        async with async_session()() as session:
            partner = await session.get(Partner, partner_id)
            if partner is None:
                return None
            result = await session.execute(
                select(PartnerPolicy)
                .where(PartnerPolicy.partner_id == partner_id)
                .order_by(PartnerPolicy.version.desc())
            )
            return list(result.scalars().all())

    async def get_policy(
        self, partner_id: str, version: Optional[int] = None
    ) -> Optional[PartnerPolicy]:
        async with async_session()() as session:
            query = select(PartnerPolicy).where(PartnerPolicy.partner_id == partner_id)
            if version is not None:
                query = query.where(PartnerPolicy.version == version)
            else:
                query = query.where(
                    PartnerPolicy.status == PolicyStatus.active.value
                )
            result = await session.execute(query)
            return result.scalars().first()

    # ── Widening detection (drives whether AWE approval is required) ──────────

    @staticmethod
    def _is_widening(data, active: Optional[PartnerPolicy]) -> bool:
        """True if `data` grants anything the current active policy did not — a
        larger allowed set, or a longer validity/data-life. The first policy
        (no active prior) counts as a widening (a grant from nothing)."""
        if active is None:
            return True
        for field in (
            "allowed_data_scopes",
            "allowed_purposes",
            "allowed_subject_id_types",
            "allowed_signing_algs",
        ):
            new_set = set(getattr(data, field, None) or [])
            old_set = set(getattr(active, field, None) or [])
            if new_set - old_set:
                return True
        if PartnerService._duration_loosened(
            data.max_validity_duration, active.max_validity_duration
        ):
            return True
        if PartnerService._duration_loosened(data.data_life, active.data_life):
            return True
        # Dropping the authentication requirement is a widening in the same sense
        # a larger scope set is: the partner reaches the same data with less proof
        # from the subject. It gates a fetch, not just the consent screen, so a
        # version that removes it must go through approval rather than take
        # effect the moment it is posted.
        if (active.required_auth_method or "") and not (
                getattr(data, "required_auth_method", None) or ""):
            return True
        # Leaving consent behind is the largest widening available: it does not
        # loosen a limit on what the subject agreed to, it removes the subject
        # from the decision. Nothing about that should take effect the moment
        # someone posts it.
        old_basis = getattr(active, "lawful_basis", "consent") or "consent"
        new_basis = getattr(data, "lawful_basis", "consent") or "consent"
        if old_basis == "consent" and new_basis != "consent":
            return True
        return False

    @staticmethod
    def _duration_loosened(new: Optional[str], old: Optional[str]) -> bool:
        """True if ISO-8601 duration `new` permits a LONGER window than `old`.
        None means "no cap" (widest). On a parse error, err toward requiring
        approval (return True)."""
        if new == old:
            return False
        if new is None:  # removed the cap → wider
            return old is not None
        if old is None:  # added a cap → narrower
            return False
        try:
            return iso_duration_to_timedelta(new) > iso_duration_to_timedelta(old)
        except Exception:
            return True

    # ── Hot path: cached verification material ───────────────────────────────

    async def get_verification_material(self, audience: str) -> Optional[dict]:
        """Return the active partner and its active policy by audience — cached
        per pod for the validation hot path.

        Partner public keys are NOT included here: they are owned by the Partner
        Management service and fetched separately (and cached with their own
        discipline) by the shared fastapi-common CryptoHelper (partner-mgmt
        backend) during consent-JWS verification, keyed by the partner's
        ``partner_mgmt_id``. This method only resolves the onboarded party +
        policy. Returns None if the partner is unknown or suspended.

        Shape: {"partner": Partner, "policy": PartnerPolicy | None}
        """
        if _config.partner_cache_enabled:
            cached = self._cache.get(audience)
            if cached is not None:
                return cached

        async with async_session()() as session:
            result = await session.execute(
                select(Partner).where(
                    Partner.audience == audience,
                    Partner.status == PartnerStatus.active.value,
                )
            )
            partner = result.scalars().first()
            if partner is None:
                return None

            policy_result = await session.execute(
                select(PartnerPolicy).where(
                    PartnerPolicy.partner_id == partner.id,
                    PartnerPolicy.status == PolicyStatus.active.value,
                )
            )
            policy = policy_result.scalars().first()

        material = {"partner": partner, "policy": policy}
        if _config.partner_cache_enabled:
            self._cache.set(audience, material)
        return material

    def _invalidate(self, audience: Optional[str]) -> None:
        if audience:
            self._cache.invalidate(audience)

    async def count_partners(self) -> int:
        async with async_session()() as session:
            result = await session.execute(select(func.count(Partner.id)))
            return int(result.scalar() or 0)
