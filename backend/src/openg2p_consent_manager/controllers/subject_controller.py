import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import Depends, Query
from fastapi.responses import JSONResponse
from openg2p_fastapi_common.controller import BaseController

from ..auth import get_current_subject
from ..config import Settings
from ..schemas.common import Paginated
from ..schemas.lifecycle import (
    ArtefactResponse,
    ConsentRequestResponse,
    RevokeRequest,
    RevokeResponse,
)
from ..services import ConsentService, LifecycleService
from ..services.consent_service import VIEW_ALL

_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)


def _artefact_response(artefact, meta: Optional[Dict[str, dict]] = None) -> ArtefactResponse:
    resp = ArtefactResponse.model_validate(artefact)
    resp.consent_id = artefact.id
    for key, value in ((meta or {}).get(artefact.id) or {}).items():
        setattr(resp, key, value)
    return resp


class SubjectController(BaseController):
    """GDPR data-subject rights — access and withdraw. Scoped to the caller."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.consents = ConsentService.get_component()
        self.lifecycle = LifecycleService.get_component()
        self.router.prefix += "/consent/v1/my"
        self.router.tags += ["Subject (GDPR)"]

        self.router.add_api_route(
            "/consents", self.list_my_consents,
            responses={200: {"model": Paginated[ArtefactResponse]}}, methods=["GET"],
        )
        # The other half of the picture. /consents answers "what have I agreed
        # to"; this answers "what is being asked of me" - which the subject
        # previously could only see by being handed a link to one request.
        self.router.add_api_route(
            "/consent-requests", self.list_my_requests,
            responses={200: {"model": Paginated[ConsentRequestResponse]}}, methods=["GET"],
        )
        self.router.add_api_route(
            "/consents/{consent_id}", self.get_my_consent,
            responses={200: {"model": ArtefactResponse}}, methods=["GET"],
        )
        # What was done under one consent: each time data actually moved
        # under it (the access records /validate wrote).
        self.router.add_api_route(
            "/consents/{consent_id}/activity", self.list_my_consent_activity,
            responses={200: {"model": List[ArtefactResponse]}}, methods=["GET"],
        )
        self.router.add_api_route(
            "/receipts/{receipt_id}", self.get_my_receipt, methods=["GET"],
        )
        self.router.add_api_route(
            "/consents/{consent_id}/revoke", self.revoke_my_consent,
            responses={200: {"model": RevokeResponse}}, methods=["POST"],
        )

    async def list_my_consents(
        self,
        subject: Dict[str, str] = Depends(get_current_subject),
        status: Optional[str] = Query(None),
        page: int = Query(1, ge=1),
        size: int = Query(20, ge=1, le=100),
        view: str = Query(VIEW_ALL, pattern="^(all|consents)$"),
    ) -> Paginated[ArtefactResponse]:
        """``view=all`` (default) lists every artefact, as this route always has.
        ``view=consents`` lists only the subject's decisions; the access
        records under each are counted in ``activity_count`` and listed
        by ``/consents/{id}/activity``."""
        result = await self.consents.list_subject_consents(
            subject["subject_id_type"], subject["subject_id_value"],
            status=status, page=page, size=size, view=view,
        )
        return Paginated[ArtefactResponse](
            items=[_artefact_response(a, result["meta"]) for a in result["items"]],
            total=result["total"], page=result["page"],
            size=result["size"], pages=result["pages"],
        )

    async def list_my_consent_activity(
        self, consent_id: str,
        subject: Dict[str, str] = Depends(get_current_subject),
    ):
        result = await self.consents.list_subject_activity(
            consent_id, subject["subject_id_type"], subject["subject_id_value"]
        )
        if result is None:
            return JSONResponse(status_code=404, content={"error": "not_found"})
        return [_artefact_response(a, result["meta"]) for a in result["items"]]

    async def list_my_requests(
        self,
        subject: Dict[str, str] = Depends(get_current_subject),
        status: Optional[str] = Query("pending"),
        page: int = Query(1, ge=1),
        size: int = Query(20, ge=1, le=100),
    ) -> Paginated[ConsentRequestResponse]:
        """Consent requests addressed to the caller. Defaults to the pending ones.

        ``required_auth_method`` is resolved per row from the asking partner's
        policy, so the screen knows which requests need a code before they can
        be granted without fetching each partner separately.
        """
        # "all" is how a caller asks for every status. Absent means pending,
        # because that is what a subject is being asked to act on and a bare
        # call to this route should not quietly return their whole history.
        result = await self.lifecycle.list_subject_requests(
            subject["subject_id_type"], subject["subject_id_value"],
            status=None if status in (None, "", "all") else status,
            page=page, size=size,
        )
        items = []
        policies: Dict[str, Optional[str]] = {}
        for req in result["items"]:
            resp = ConsentRequestResponse.model_validate(req)
            if req.partner_id not in policies:
                policy = await self.lifecycle.partners.get_policy(req.partner_id)
                policies[req.partner_id] = getattr(policy, "required_auth_method", None)
            resp.required_auth_method = policies[req.partner_id]
            items.append(resp)
        return Paginated[ConsentRequestResponse](
            items=items, total=result["total"], page=result["page"],
            size=result["size"], pages=result["pages"],
        )

    async def get_my_consent(
        self, consent_id: str,
        subject: Dict[str, str] = Depends(get_current_subject),
    ):
        artefact = await self.consents.get_subject_artefact(
            consent_id, subject["subject_id_type"], subject["subject_id_value"]
        )
        if artefact is None:
            return JSONResponse(status_code=404, content={"error": "not_found"})
        return _artefact_response(artefact)

    async def get_my_receipt(
        self, receipt_id: str,
        subject: Dict[str, str] = Depends(get_current_subject),
    ):
        receipt = await self.consents.get_receipt(receipt_id)
        if receipt is None:
            return JSONResponse(status_code=404, content={"error": "not_found"})
        # Ensure the receipt belongs to the authenticated subject.
        artefact = await self.consents.get_subject_artefact(
            receipt.consent_id, subject["subject_id_type"], subject["subject_id_value"]
        )
        if artefact is None:
            return JSONResponse(status_code=403, content={"error": "forbidden"})
        return JSONResponse(content=receipt.document)

    async def revoke_my_consent(
        self, consent_id: str,
        subject: Dict[str, str] = Depends(get_current_subject),
        data: RevokeRequest = RevokeRequest(),
    ):
        try:
            artefact = await self.consents.revoke(
                consent_id, originated_by="subject", reason=data.reason,
                subject_claims=subject,
            )
        except PermissionError:
            return JSONResponse(status_code=403, content={"error": "forbidden"})
        except ValueError as exc:
            return JSONResponse(status_code=409, content={"error": str(exc)})
        if artefact is None:
            return JSONResponse(status_code=404, content={"error": "not_found"})
        return RevokeResponse(
            consent_id=artefact.id, status=artefact.status,
            revoked_at=artefact.revoked_at or datetime.now(timezone.utc),
        )
