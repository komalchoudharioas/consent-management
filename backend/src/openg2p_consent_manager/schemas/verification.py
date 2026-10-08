from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from .common import ReasonCode, SubjectId


class ConsentObjectValidity(BaseModel):
    valid_from: datetime
    valid_until: datetime


class ConsentObject(BaseModel):
    """The partner's consent claims — the *payload* of the consent JWS.

    The signature is NOT a field here: the whole object is signed as a compact
    JWS (RFC 7515) and these are the claims recovered from its payload. The JWS
    protected header carries the ``alg`` and ``kid`` used to verify it.
    """

    jti: str
    subject_id: SubjectId
    data_controller: str
    aud: str
    purpose: Dict[str, Any]
    data_scopes: List[str]
    fetch_type: str = "oneshot"
    validity: ConsentObjectValidity
    issued_at: datetime

    # Tolerate JSON-LD framing keys (@context/@type) and any extra attributes.
    model_config = {"extra": "allow"}


class RequestContext(BaseModel):
    requested_scopes: Optional[List[str]] = None
    subject_id: Optional[SubjectId] = None


class ValidateRequest(BaseModel):
    # The partner-signed consent object, as a compact JWS (header.payload.sig).
    # CM recovers the claims from the payload and verifies the signature against
    # the partner's Partner-Management key referenced by the JWS ``kid``.
    consent_jws: str
    partner_id: Optional[str] = None
    request_context: Optional[RequestContext] = None


class DecisionLogResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    partner_id: Optional[str] = None
    consent_id: Optional[str] = None
    object_jti: Optional[str] = None
    decision: str
    reason_code: str
    detail: Optional[str] = None
    policy_version: Optional[int] = None
    created_at: datetime


class Decision(BaseModel):
    decision: str  # permit | deny
    reason_code: ReasonCode
    detail: Optional[str] = None
    consent_id: Optional[str] = None
    receipt_id: Optional[str] = None
    subject_id: Optional[SubjectId] = None
    effective_data_scopes: Optional[List[str]] = None
    valid_until: Optional[datetime] = None
    policy_version: Optional[int] = None
    # Why the data may move: "consent" (a subject grant narrowed this) or
    # "legitimate_interest" (no grant was sought; the policy ceiling is the
    # whole of the authority). Carried so callers can record WHICH it was
    # rather than inferring it from the absence of something.
    lawful_basis: str = "consent"
    # Which CM binding the decision was made for. Set on a permit so a caller
    # outside the CM (the Aggregation Layer) learns who the partner is from the
    # PDP itself instead of reading the artefact table.
    partner_id: Optional[str] = None
    partner_audience: Optional[str] = None
    evaluated_at: datetime
