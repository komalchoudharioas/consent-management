from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .common import SubjectId


class ConsentRequestCreate(BaseModel):
    subject_id: SubjectId
    partner_id: str
    purpose: Dict[str, Any]
    requested_scopes: List[str] = Field(..., min_length=1)
    validity: Optional[Dict[str, datetime]] = None  # {valid_from, valid_until}


class ConsentRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    subject_id_type: str
    subject_id_value: str
    partner_id: str
    purpose: Dict[str, Any]
    requested_scopes: List[str]
    status: str
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    created_at: datetime
    # How this subject must authenticate before they can grant, and how far
    # they have got. The screen reads these rather than guessing.
    required_auth_method: Optional[str] = None
    otp_channel: Optional[str] = None
    otp_expires_at: Optional[datetime] = None
    otp_verified_at: Optional[datetime] = None


class AuthenticateRequest(BaseModel):
    id_token: str


class AuthenticateResponse(BaseModel):
    request_id: str
    auth_context_id: str
    token_validated: bool
    auth_method: Optional[str] = None


class IssueOtpResponse(BaseModel):
    """What the consent screen needs to render the code-entry step. The code
    itself is never in here — only where it went and when it dies."""

    request_id: str
    otp_required: bool = True
    otp_channel: Optional[str] = None
    otp_expires_at: Optional[datetime] = None
    otp_provider: Optional[str] = None
    message: Optional[str] = None


class VerifyOtpRequest(BaseModel):
    otp: str = Field(min_length=4, max_length=10)


class ApproveRequest(BaseModel):
    granted_scopes: List[str] = Field(..., min_length=1)


class ArtefactResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    consent_id: Optional[str] = None
    subject_id_type: str
    subject_id_value: str
    partner_id: str
    purpose: Dict[str, Any]
    effective_data_scopes: List[str]
    status: str
    source: str
    valid_from: datetime
    valid_until: datetime
    created_at: datetime
    revoked_at: Optional[datetime] = None
    # Set on the subject routes only. What the row is (consent | access), the
    # consent it hangs off when it is not one itself, and how many rows hang
    # off it when it is.
    record_kind: Optional[str] = None
    derived_from: Optional[str] = None
    activity_count: Optional[int] = None
    partner_name: Optional[str] = None
    controller_id: Optional[str] = None


class DenyRequest(BaseModel):
    reason: Optional[str] = None


class RevokeRequest(BaseModel):
    reason: Optional[str] = None
    originated_by: str = "controller"  # subject | controller | partner


class RevokeResponse(BaseModel):
    consent_id: str
    status: str
    revoked_at: datetime
