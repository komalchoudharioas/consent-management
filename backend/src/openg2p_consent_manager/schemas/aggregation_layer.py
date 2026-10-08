"""Bodies for the service APIs the Aggregation Layer calls."""
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from .common import SubjectId


class GrantBinding(BaseModel):
    registry: str = Field(..., examples=["farmer"])
    audience: str = Field(..., examples=["aggregation-layer-farmer"])
    scopes: List[str] = Field(default_factory=list)


class GrantsCreate(BaseModel):
    aggregation_id: str
    subject_id: SubjectId
    issuer: str = Field(..., examples=["aggregation-layer"])
    auth_method: Literal["otp", "consent", "none"]
    auth_timestamp: Optional[datetime] = None
    lawful_basis: Literal["consent", "legitimate_interest"] = "consent"
    otp_channel: Optional[str] = None
    purpose: Dict[str, Any] = Field(default_factory=dict)
    valid_until: datetime
    reuse_min_remaining_sec: int = 150
    bindings: List[GrantBinding] = Field(default_factory=list)
    # Which consent these grants come from, for My consents grouping. One of:
    # the consent request the aggregator raised (approved on the screen), or
    # the consent_id /validate returned when the partner already held consent.
    consent_request_id: Optional[str] = None
    root_consent_id: Optional[str] = None


class GrantsResponse(BaseModel):
    auth_context_id: str
    minted: List[str]
    reused: List[str]
    skipped: List[Dict[str, str]]


class GrantedScopesResponse(BaseModel):
    request_id: str
    status: str
    partner_id: str
    subject_id: SubjectId
    granted_scopes: List[str]
    consent_id: Optional[str] = None
    otp_verified_at: Optional[str] = None
    otp_channel: Optional[str] = None
    otp_provider: Optional[str] = None
