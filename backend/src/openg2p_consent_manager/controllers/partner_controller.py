import logging
from typing import Optional

from fastapi import Depends, Query
from fastapi.responses import JSONResponse
from openg2p_fastapi_common.controller import BaseController

from ..auth import require_any_role, require_role
from ..config import Settings
from ..models import PolicyStatus
from ..schemas.partner import (
    PartnerCreate,
    PartnerResponse,
    PartnerUpdate,
    PolicyResponse,
    PolicyUpsert,
)
from ..services import PartnerService
from ..services.awe_client import AweClient, AweClientError

_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)

_NOT_FOUND = JSONResponse(status_code=404, content={"error": "not_found"})


class PartnerController(BaseController):
    """Administrative policy-binding + data-share-policy management.

    A "partner" here is a policy BINDING: partner identity, lifecycle and signing
    keys are owned by the Partner Management service (CM stores only the PM
    reference `partner_mgmt_id` and fetches keys at verification time). Widening a
    binding's data-share policy is gated behind AWE approval (see upsert_policy).
    """

    # TODO(partner-delete): add a SOFT delete for bindings (audit-safe).
    #   A partner is referenced by ConsentArtefact / ConsentReceipt / ConsentRequest
    #   / DecisionLog / AuditLog, so it must NEVER be hard-deleted — that would
    #   orphan the audit trail and break non-repudiation. Plan:
    #     1. Add an `archived` value to PartnerStatus (alongside active/suspended);
    #        like suspended it fails validation (validate filters status==active).
    #     2. Add DELETE /partners/{id} that does a SOFT delete: set status=archived,
    #        keep the row, return 200.
    #     3. Switch the sanity e2e cleanup from PATCH suspended -> DELETE (archived).
    #   Until then, "delete" = PATCH /partners/{id} {status: "suspended"}.

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.partners = PartnerService.get_component()
        self.awe = AweClient.get_component()
        self.router.prefix += "/consent/v1/partners"
        self.router.tags += ["Partners & Policy"]

        # All partner/policy admin endpoints require the admin role.
        admin = [Depends(require_role(_config.auth_admin_role))]
        # Read-only lookups a platform service (the Aggregation Layer) needs
        # also accept the service role, so that client never holds admin.
        admin_or_service = [Depends(require_any_role(
            _config.auth_admin_role, _config.auth_service_role))]

        # Before "/{partner_id}..." so the literal segment is matched first.
        self.router.add_api_route(
            "/by-audience/{audience}", self.get_partner_by_audience,
            dependencies=admin_or_service,
            responses={200: {"model": PartnerResponse}}, methods=["GET"],
        )

        self.router.add_api_route(
            "", self.list_partners, dependencies=admin,
            responses={200: {"model": list[PartnerResponse]}}, methods=["GET"],
        )
        self.router.add_api_route(
            "", self.create_partner, dependencies=admin,
            responses={201: {"model": PartnerResponse}}, methods=["POST"], status_code=201,
        )
        self.router.add_api_route(
            "/{partner_id}", self.get_partner, dependencies=admin,
            responses={200: {"model": PartnerResponse}}, methods=["GET"],
        )
        self.router.add_api_route(
            "/{partner_id}", self.update_partner, dependencies=admin,
            responses={200: {"model": PartnerResponse}}, methods=["PATCH"],
        )
        self.router.add_api_route(
            "/{partner_id}/policy", self.upsert_policy, dependencies=admin,
            responses={200: {"model": PolicyResponse}}, methods=["PUT"],
        )
        self.router.add_api_route(
            "/{partner_id}/policy", self.get_policy, dependencies=admin_or_service,
            responses={200: {"model": PolicyResponse}}, methods=["GET"],
        )
        self.router.add_api_route(
            "/{partner_id}/policies", self.list_policies, dependencies=admin,
            responses={200: {"model": list[PolicyResponse]}}, methods=["GET"],
        )

    async def list_partners(
        self,
        controller_id: Optional[str] = Query(None),
        status: Optional[str] = Query(None),
    ):
        partners = await self.partners.list_partners(controller_id=controller_id, status=status)
        return [PartnerResponse.model_validate(p) for p in partners]

    async def create_partner(self, data: PartnerCreate):
        # A binding is created active; partner identity onboarding is PM's job.
        partner = await self.partners.create_partner(data)
        return PartnerResponse.model_validate(partner)

    async def get_partner_by_audience(self, audience: str):
        partner = await self.partners.get_partner_by_audience(audience)
        if partner is None:
            return _NOT_FOUND
        return PartnerResponse.model_validate(partner)

    async def get_partner(self, partner_id: str):
        partner = await self.partners.get_partner(partner_id)
        if partner is None:
            return _NOT_FOUND
        return PartnerResponse.model_validate(partner)

    async def update_partner(self, partner_id: str, data: PartnerUpdate):
        partner = await self.partners.update_partner(partner_id, data)
        if partner is None:
            return _NOT_FOUND
        return PartnerResponse.model_validate(partner)

    async def upsert_policy(self, partner_id: str, data: PolicyUpsert):
        partner = await self.partners.get_partner(partner_id)
        if partner is None:
            return _NOT_FOUND
        policy = await self.partners.upsert_policy(partner_id, data)
        if policy is None:
            return _NOT_FOUND

        # A widening policy comes back `pending` — submit it to AWE for approval.
        # It stays pending (the prior active policy remains in force) until AWE's
        # terminal webhook activates it. If AWE is unreachable, surface 502 but
        # keep the pending version so it can be resubmitted.
        if policy.status == PolicyStatus.pending.value:
            context = {
                "partner_label": partner.name or partner.partner_mgmt_id or partner.audience,
                "partner_mgmt_id": partner.partner_mgmt_id,
                "controller_id": partner.controller_id,
                "policy_version": policy.version,
                "allowed_data_scopes": policy.allowed_data_scopes,
                "allowed_purposes": policy.allowed_purposes,
            }
            try:
                request_id = await self.awe.create_request(
                    artifact_type="consent_manager.policy_change",
                    artifact_id=policy.id,
                    context=context,
                )
                await self.partners.set_policy_awe_request_id(policy.id, request_id)
                policy.awe_request_id = request_id
            except AweClientError as exc:
                _logger.error("AWE policy-change submit failed for %s: %s", policy.id, exc)
                return JSONResponse(
                    status_code=502,
                    content={
                        "error": "awe_submit_failed",
                        "message": exc.message,
                        "policy_id": policy.id,
                    },
                )

        return PolicyResponse.model_validate(policy)

    async def get_policy(self, partner_id: str, version: Optional[int] = Query(None)):
        policy = await self.partners.get_policy(partner_id, version)
        if policy is None:
            return _NOT_FOUND
        return PolicyResponse.model_validate(policy)

    async def list_policies(self, partner_id: str):
        policies = await self.partners.list_policies(partner_id)
        if policies is None:
            return _NOT_FOUND
        return [PolicyResponse.model_validate(p) for p in policies]
