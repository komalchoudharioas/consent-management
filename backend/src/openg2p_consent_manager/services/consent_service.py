import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from openg2p_fastapi_common.service import BaseService
from sqlalchemy import select

from ..config import Settings
from ..db import async_session
from ..models import (
    ArtefactSource,
    ArtefactStatus,
    ConsentArtefact,
    ConsentReceipt,
    Partner,
    RevocationRecord,
)

#: What an artefact is, from the subject's side of the screen.
#:   consent   a decision the subject (or a lawful basis) made - the thing
#:             they can read, and withdraw
#:   access    a record that data actually moved under a consent
KIND_CONSENT, KIND_ACCESS = "consent", "access"

VIEW_ALL, VIEW_CONSENTS = "all", "consents"

_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class ConsentService(BaseService):
    """Status, receipts, revocation, expiry, and subject-scoped queries."""

    async def get_status(self, consent_id: str) -> Optional[dict]:
        async with async_session()() as session:
            artefact = await session.get(ConsentArtefact, consent_id)
            if artefact is None:
                return None
            now = datetime.now(timezone.utc)
            status = artefact.status
            # Lazy expiry — treat a lapsed artefact as expired even before the job runs.
            if status == ArtefactStatus.active.value and _aware(artefact.valid_until) < now:
                artefact.status = ArtefactStatus.expired.value
                artefact.expired_at = now
                await session.commit()
                status = artefact.status
            return {
                "consent_id": artefact.id,
                "status": status,
                "valid_until": artefact.valid_until,
                "checked_at": now,
            }

    async def get_receipt(self, receipt_id: str) -> Optional[ConsentReceipt]:
        async with async_session()() as session:
            return await session.get(ConsentReceipt, receipt_id)

    async def get_receipt_by_consent(self, consent_id: str) -> Optional[ConsentReceipt]:
        async with async_session()() as session:
            result = await session.execute(
                select(ConsentReceipt).where(ConsentReceipt.consent_id == consent_id)
            )
            return result.scalars().first()

    async def revoke(
        self, consent_id: str, originated_by: str, reason: Optional[str],
        subject_claims: Optional[dict] = None,
    ) -> Optional[ConsentArtefact]:
        """Revoke an active consent. Append-only; raises ValueError on conflict.

        Returns None if not found. If subject_claims is given, enforces that the
        caller is the subject (used by the subject API).
        """
        async with async_session()() as session:
            artefact = await session.get(ConsentArtefact, consent_id)
            if artefact is None:
                return None
            if subject_claims is not None and (
                artefact.subject_id_type != subject_claims.get("subject_id_type")
                or artefact.subject_id_value != subject_claims.get("subject_id_value")
            ):
                raise PermissionError("not the subject of this consent")
            if artefact.status != ArtefactStatus.active.value:
                raise ValueError(f"consent already '{artefact.status}'")

            now = datetime.now(timezone.utc)
            artefact.status = ArtefactStatus.revoked.value
            artefact.revoked_at = now
            session.add(
                RevocationRecord(
                    consent_id=consent_id, originated_by=originated_by, reason=reason
                )
            )
            # Same transaction: a withdrawal that committed while the records
            # it covers stayed active would read as still in force.
            await self._cascade_revoke(session, artefact, originated_by, now)
            await session.commit()
            await session.refresh(artefact)
            return artefact

    async def _cascade_revoke(self, session, artefact: ConsentArtefact,
                              originated_by: str, now: datetime) -> None:
        """Withdrawing a consent withdraws everything recorded under it.

        Every ACTIVE row whose ``derived_from`` is this consent - the access
        records /validate wrote while the consent was in force - is revoked,
        each with its own RevocationRecord naming the parent, so none of them
        reads as still in force.

        Withdrawing an access record on its own cascades nothing - it is not a
        consent, and nothing hangs off it.
        """
        rows = (await session.execute(
            select(ConsentArtefact).where(
                ConsentArtefact.subject_id_type == artefact.subject_id_type,
                ConsentArtefact.subject_id_value == artefact.subject_id_value,
            )
        )).scalars().all()
        meta = await self._classify(session, rows)
        own = meta.get(artefact.id) or {}
        if own.get("record_kind") != KIND_CONSENT or own.get("derived_from"):
            return

        children = [a for a in rows
                    if meta[a.id]["derived_from"] == artefact.id
                    and a.status == ArtefactStatus.active.value]
        for child in children:
            child.status = ArtefactStatus.revoked.value
            child.revoked_at = now
            session.add(RevocationRecord(
                consent_id=child.id, originated_by=originated_by,
                reason="parent consent %s withdrawn" % artefact.id))

        _logger.info("Consent %s withdrawn: %d derived row(s) revoked",
                     artefact.id, len(children))

    async def expire_stale(self) -> int:
        """Mark active artefacts past valid_until as expired. Safe to run from a
        CronJob across replicas — each row transitions once and idempotently.
        """
        now = datetime.now(timezone.utc)
        async with async_session()() as session:
            result = await session.execute(
                select(ConsentArtefact).where(
                    ConsentArtefact.status == ArtefactStatus.active.value,
                    ConsentArtefact.valid_until < now,
                )
            )
            stale = result.scalars().all()
            for artefact in stale:
                artefact.status = ArtefactStatus.expired.value
                artefact.expired_at = now
            await session.commit()
            count = len(stale)
        if count:
            _logger.info("Expired %d stale consent artefacts", count)
        return count

    # ── Subject-scoped queries (GDPR access) ─────────────────────────────────

    async def list_subject_consents(
        self, subject_id_type: str, subject_id_value: str,
        status: Optional[str] = None, page: int = 1, size: int = 20,
        view: str = VIEW_ALL,
    ) -> dict:
        """The subject's artefacts, newest first, each labelled with what it is.

        ``view=all`` (the default, and the route's behaviour before grouping
        existed) returns every row. ``view=consents`` returns only the decisions
        - every fetch a partner makes under a consent writes an access record,
        and those belong UNDER the consent, not beside it. Nothing is dropped: they are counted on their parent
        (``activity_count``) and listed by ``list_subject_activity``.

        Grouping needs the whole set, because a row's parent is found through
        other rows, so this reads every artefact the subject has and pages in
        memory. A subject's history is small enough for that; a partner's would
        not be, which is why only the subject routes do it.
        """
        async with async_session()() as session:
            rows = (await session.execute(
                select(ConsentArtefact).where(
                    ConsentArtefact.subject_id_type == subject_id_type,
                    ConsentArtefact.subject_id_value == subject_id_value,
                ).order_by(ConsentArtefact.created_at.desc())
            )).scalars().all()
            meta = await self._classify(session, rows)

        counts: Dict[str, int] = {}
        for m in meta.values():
            if m["derived_from"]:
                counts[m["derived_from"]] = counts.get(m["derived_from"], 0) + 1
        for artefact_id, m in meta.items():
            m["activity_count"] = counts.get(artefact_id, 0)

        selected = [
            a for a in rows
            if (not status or a.status == status)
            and (view != VIEW_CONSENTS or not meta[a.id]["derived_from"])
        ]
        total = len(selected)
        start = (page - 1) * size
        pages = max(1, (total + size - 1) // size)
        return {"items": selected[start:start + size], "meta": meta,
                "total": total, "page": page, "size": size, "pages": pages}

    async def list_subject_activity(
        self, consent_id: str, subject_id_type: str, subject_id_value: str,
    ) -> Optional[dict]:
        """Every access record that hangs off one of the subject's
        consents, newest first. None when the consent is not theirs."""
        async with async_session()() as session:
            rows = (await session.execute(
                select(ConsentArtefact).where(
                    ConsentArtefact.subject_id_type == subject_id_type,
                    ConsentArtefact.subject_id_value == subject_id_value,
                ).order_by(ConsentArtefact.created_at.desc())
            )).scalars().all()
            if not any(a.id == consent_id for a in rows):
                return None
            meta = await self._classify(session, rows)
        items = [a for a in rows if meta[a.id]["derived_from"] == consent_id]
        return {"items": items, "meta": meta}

    async def _classify(self, session, rows: List[ConsentArtefact]) -> Dict[str, dict]:
        """Label each artefact and find the consent it was derived from.

        Every link used here is one the write paths already record; nothing is
        inferred from timing.

        * ``lifecycle.approve`` writes the subject's consent with the
          AuthContext of the act that approved it.
        * ``verification._permit`` copies the grant's AuthContext onto the
          access record it writes (gap B8), so an access record points at
          whichever consent let it through.

        A row whose parent cannot be found - a consent wiped from under it, a
        row older than these links - is left at the top level. Hiding a record
        the subject cannot then reach from anywhere would be the one wrong
        answer.
        """
        partner_ids = {a.partner_id for a in rows}
        partners: Dict[str, Partner] = {}
        if partner_ids:
            partners = {p.id: p for p in (await session.execute(
                select(Partner).where(Partner.id.in_(partner_ids))
            )).scalars().all()}

        def kind_of(a: ConsentArtefact) -> str:
            if a.source == ArtefactSource.originated.value:
                return KIND_CONSENT
            # An embedded object with no subject grant behind it IS the consent:
            # a partner-held object, or an internal partner's legitimate interest.
            return KIND_ACCESS if a.auth_context_id else KIND_CONSENT

        kinds = {a.id: kind_of(a) for a in rows}
        # The subject's own grants, reachable by the act that created them.
        by_ctx = {a.auth_context_id: a.id for a in rows
                  if kinds[a.id] == KIND_CONSENT and a.auth_context_id}

        meta: Dict[str, dict] = {}
        for a in rows:
            kind = kinds[a.id]
            parent = None
            if kind != KIND_CONSENT:
                parent = by_ctx.get(a.auth_context_id)
            partner = partners.get(a.partner_id)
            meta[a.id] = {
                "record_kind": kind,
                "derived_from": parent if parent != a.id else None,
                "partner_name": (partner.name or partner.audience) if partner else None,
                "controller_id": a.controller_id,
            }
        return meta

    async def get_subject_artefact(
        self, consent_id: str, subject_id_type: str, subject_id_value: str
    ) -> Optional[ConsentArtefact]:
        async with async_session()() as session:
            artefact = await session.get(ConsentArtefact, consent_id)
            if artefact is None or (
                artefact.subject_id_type != subject_id_type
                or artefact.subject_id_value != subject_id_value
            ):
                return None
            return artefact
