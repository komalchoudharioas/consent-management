import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from openg2p_fastapi_common.service import BaseService
from sqlalchemy import func, select, update

from ..config import Settings
from ..db import async_session
from ..models import (
    AggregationRequest,
    AggregationStatus,
    ArtefactSource,
    ArtefactStatus,
    AuthContext,
    ConsentArtefact,
    ConsentReceipt,
    Partner,
    RevocationRecord,
)

#: What an artefact is, from the subject's side of the screen.
#:   consent         a decision the subject (or a lawful basis) made - the thing
#:                   they can read, and withdraw
#:   registry_grant  the aggregator's per-registry grant, minted from that
#:                   decision so the registry's PDP will let the fetch through
#:   access          a record that data actually moved under a consent
KIND_CONSENT, KIND_GRANT, KIND_ACCESS = "consent", "registry_grant", "access"

VIEW_ALL, VIEW_CONSENTS = "all", "consents"

#: Aggregation states a withdrawal can still stop. ``pending_consent`` waits on
#: a different, not-yet-approved request; ``delivering`` has already sent.
_CANCELLABLE = tuple(s.value for s in (
    AggregationStatus.received, AggregationStatus.pending_otp,
    AggregationStatus.verified, AggregationStatus.queued,
    AggregationStatus.fetching, AggregationStatus.fetched))

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
            # Same transaction: a withdrawal that committed while the grants
            # it covers stayed active would be a window in which the registry
            # still says yes.
            await self._cascade_revoke(session, artefact, originated_by, now)
            await session.commit()
            await session.refresh(artefact)
            return artefact

    async def _cascade_revoke(self, session, artefact: ConsentArtefact,
                              originated_by: str, now: datetime) -> None:
        """Withdrawing a consent stops everything that was running on it.

        Without this, the per-registry grants minted from the consent stayed
        active for their five minutes, and a queued or retrying fan-out in that
        window still fetched: the registry's PDP reads the grant, not the
        consent it came from.

        * Every ACTIVE row whose ``derived_from`` is this consent is revoked,
          each with its own RevocationRecord naming the parent - the grants, so
          the registries deny at once, and the access records, so none of them
          reads as still in force.
        * Every aggregation of this partner for this subject that has not yet
          been delivered is rejected with ``consent_withdrawn``, unless the
          subject still holds ANOTHER active consent for the same partner (then
          that consent is what the fetch runs on). Each fan-out stage claims
          its row by status, so a rejected row is skipped by fetch, delivery
          and every retry. ``delivering`` is left alone: the POST is already
          on the wire and cannot be recalled.

        Withdrawing a grant or access record on its own cascades nothing - it
        is not a consent, and nothing hangs off it.
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

        still_consented = any(
            a.id != artefact.id and a.partner_id == artefact.partner_id
            and a.status == ArtefactStatus.active.value
            and meta[a.id]["record_kind"] == KIND_CONSENT
            and not meta[a.id]["derived_from"]
            and _aware(a.valid_until) > now
            for a in rows)
        cancelled = 0
        if not still_consented:
            result = await session.execute(
                update(AggregationRequest)
                .where(AggregationRequest.partner_id == artefact.partner_id,
                       AggregationRequest.subject_id_type == artefact.subject_id_type,
                       AggregationRequest.subject_id_value == artefact.subject_id_value,
                       AggregationRequest.status.in_(_CANCELLABLE))
                .values(status=AggregationStatus.rejected.value,
                        failure_reason="consent_withdrawn",
                        claimed_by=None, claimed_at=None, next_retry_at=None)
            )
            cancelled = result.rowcount or 0
            # And in the Aggregation Layer when it runs as its own service.
            # Cancelling early is the safe direction, so this need not wait for
            # the caller's commit.
            from . import aggregation_events

            aggregation_events.publish(aggregation_events.EVENT_WITHDRAWN, {
                "consent_id": artefact.id,
                "partner_id": artefact.partner_id,
                "subject_id": {"type": artefact.subject_id_type,
                               "value": artefact.subject_id_value},
            })
        _logger.info("Consent %s withdrawn: %d derived row(s) revoked, %d "
                     "in-flight aggregation(s) cancelled",
                     artefact.id, len(children), cancelled)

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
        - an aggregated fetch writes one consent plus a grant and an access
        record per registry, and those six belong UNDER the consent, not beside
        it. Nothing is dropped: they are counted on their parent
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
        """Every grant and access record that hangs off one of the subject's
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
        inferred from timing except the one case noted below.

        * ``lifecycle.approve`` writes the subject's consent with an AuthContext
          whose ``consent_request_id`` is the request they approved.
        * ``aggregator._mint_grants`` writes one AuthContext per aggregation
          (``auth_provider`` = the aggregator, ``consent_request_id`` = the
          aggregation id) and a grant per registry pointing at it.
        * ``verification._permit`` copies the grant's AuthContext onto the
          access record it writes (gap B8), so an access record points at
          whichever grant let it through.

        A row whose parent cannot be found - a consent wiped from under it, a
        row older than these links - is left at the top level. Hiding a record
        the subject cannot then reach from anywhere would be the one wrong
        answer.
        """
        agg_issuer = _config.aggregator_issuer
        ctx_ids = {a.auth_context_id for a in rows if a.auth_context_id}
        ctxs: Dict[str, AuthContext] = {}
        if ctx_ids:
            ctxs = {c.id: c for c in (await session.execute(
                select(AuthContext).where(AuthContext.id.in_(ctx_ids))
            )).scalars().all()}

        def is_agg(ctx_id: Optional[str]) -> bool:
            # The in-process aggregator signs as aggregator_issuer; the external
            # Aggregation Layer has its own issuer, but both record the
            # aggregation id in the claims.
            ctx = ctxs.get(ctx_id) if ctx_id else None
            return bool(ctx and (ctx.auth_provider == agg_issuer
                                 or "aggregation_id" in (ctx.verified_claims or {})))

        agg_ids = {ctxs[c].consent_request_id for c in ctx_ids if is_agg(c)}
        aggs: Dict[str, AggregationRequest] = {}
        if agg_ids:
            aggs = {g.id: g for g in (await session.execute(
                select(AggregationRequest).where(AggregationRequest.id.in_(agg_ids))
            )).scalars().all()}

        partner_ids = {a.partner_id for a in rows}
        partners: Dict[str, Partner] = {}
        if partner_ids:
            partners = {p.id: p for p in (await session.execute(
                select(Partner).where(Partner.id.in_(partner_ids))
            )).scalars().all()}

        def kind_of(a: ConsentArtefact) -> str:
            if a.source == ArtefactSource.originated.value:
                return KIND_GRANT if is_agg(a.auth_context_id) else KIND_CONSENT
            # An embedded object with no subject grant behind it IS the consent:
            # a partner-held object, or an internal partner's legitimate interest.
            return KIND_ACCESS if a.auth_context_id else KIND_CONSENT

        kinds = {a.id: kind_of(a) for a in rows}
        # The subject's own grants, reachable by the act that created them.
        by_ctx = {a.auth_context_id: a.id for a in rows
                  if kinds[a.id] == KIND_CONSENT and a.auth_context_id}
        by_request = {ctxs[c].consent_request_id: a for c, a in by_ctx.items() if c in ctxs}

        by_id = {a.id: a for a in rows}

        def root_of_aggregation(ctx_id: str) -> Optional[str]:
            # The external Aggregation Layer states the link when it records the
            # grant (POST /consent/v1/grants), so nothing is read from its tables.
            claims = ctxs[ctx_id].verified_claims or {}
            if claims.get("consent_request_id"):
                return by_request.get(claims["consent_request_id"])
            if claims.get("root_consent_id"):
                obj = by_id.get(claims["root_consent_id"])
                if obj is None:
                    return None
                if kinds[obj.id] == KIND_CONSENT:
                    return obj.id
                return by_ctx.get(obj.auth_context_id)
            agg = aggs.get(ctxs[ctx_id].consent_request_id)
            if agg is None:
                return None
            # Raised by the aggregator and approved on the consent screen.
            if agg.consent_request_id:
                return by_request.get(agg.consent_request_id)
            # The partner already held consent: seek validated its object just
            # before writing the aggregation row, so the newest object for that
            # binding at that moment is the one. The only timing-based link.
            seen = [a for a in rows
                    if a.partner_id == agg.partner_id
                    and a.source == ArtefactSource.embedded.value
                    and a.created_at and agg.created_at
                    and a.created_at <= agg.created_at]
            if not seen:
                return None
            obj = max(seen, key=lambda a: a.created_at)
            if kinds[obj.id] == KIND_CONSENT:
                return obj.id
            return by_ctx.get(obj.auth_context_id)

        meta: Dict[str, dict] = {}
        for a in rows:
            kind = kinds[a.id]
            parent = None
            if kind != KIND_CONSENT:
                parent = (root_of_aggregation(a.auth_context_id)
                          if is_agg(a.auth_context_id)
                          else by_ctx.get(a.auth_context_id))
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
