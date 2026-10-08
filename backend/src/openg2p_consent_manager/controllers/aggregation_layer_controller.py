"""Service APIs for the Aggregation Layer (service role only).

    POST /consent/v1/grants                                  record the subject's grant
    GET  /consent/v1/consent-requests/{id}/granted-scopes    what an approval granted

The Aggregation Layer used to do both by writing and reading CM tables from
inside this process. It now runs as its own service and calls these instead.
"""
import logging

from fastapi import Depends
from fastapi.responses import JSONResponse
from openg2p_fastapi_common.controller import BaseController

from ..auth import require_any_role
from ..config import Settings
from ..schemas.aggregation_layer import (
    GrantedScopesResponse,
    GrantsCreate,
    GrantsResponse,
)
from ..services.aggregation_layer_service import AggregationLayerService

_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)


class AggregationLayerController(BaseController):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.service = AggregationLayerService.get_component()
        self.router.prefix += "/consent/v1"
        self.router.tags += ["Aggregation Layer (service)"]

        service = [Depends(require_any_role(_config.auth_service_role))]
        self.router.add_api_route(
            "/grants", self.record_grants, dependencies=service,
            responses={201: {"model": GrantsResponse}}, methods=["POST"], status_code=201,
        )
        self.router.add_api_route(
            "/consent-requests/{request_id}/granted-scopes", self.granted_scopes,
            dependencies=service,
            responses={200: {"model": GrantedScopesResponse}}, methods=["GET"],
        )

    async def record_grants(self, data: GrantsCreate):
        return GrantsResponse(**await self.service.record_grants(data))

    async def granted_scopes(self, request_id: str):
        result = await self.service.granted_scopes(request_id)
        if result is None:
            return JSONResponse(status_code=404, content={"error": "not_found"})
        return GrantedScopesResponse(**result)
