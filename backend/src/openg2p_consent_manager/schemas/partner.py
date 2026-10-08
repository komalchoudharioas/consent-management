from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# A "partner" here is CM's policy *binding* (PM owns the partner identity/keys).
class PartnerCreate(BaseModel):
    # Reference to the Partner-Management partner whose keys verify this partner's
    # consent objects. When omitted, CM falls back to `audience` as the PM ref.
    partner_mgmt_id: Optional[str] = Field(None, max_length=255)
    audience: str = Field(..., min_length=1, max_length=255)
    controller_id: str = Field(..., min_length=1, max_length=255)
    # Optional display label (identity is authoritative in Partner Management).
    name: Optional[str] = Field(None, max_length=255)


class PartnerUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None  # active | suspended
    partner_mgmt_id: Optional[str] = None


class PartnerResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: Optional[str] = None
    audience: str
    controller_id: str
    status: str
    partner_mgmt_id: Optional[str] = None
    created_at: datetime


class PolicyUpsert(BaseModel):
    allowed_data_scopes: List[str] = Field(default_factory=list)
    allowed_purposes: List[str] = Field(default_factory=list)
    allowed_subject_id_types: List[str] = Field(default_factory=list)
    allowed_signing_algs: List[str] = Field(default_factory=lambda: ["EdDSA", "ES256"])
    max_validity_duration: Optional[str] = Field(None, examples=["P1Y"])
    fetch_type: str = "oneshot"
    max_fetch_frequency: Optional[str] = None
    data_life: Optional[str] = Field(None, examples=["P30D"])
    # How this partner's subjects must prove who they are on the consent
    # screen. "otp" demands a one-time code before approve accepts the grant;
    # None means an OIDC id_token is enough. Readable through the policy API,
    # so a service fetching on the partner's behalf can apply the same rule.
    required_auth_method: Optional[str] = Field(
        None, examples=["otp"],
        description='"otp" or null. Anything else is rejected.')

    # Why this partner may hold the data at all. "consent" (the default) means a
    # subject grant is required; "legitimate_interest" means the controller's own
    # basis carries it and no grant is sought — for a partner inside the
    # controller's own organisation. See PartnerPolicy.lawful_basis.
    lawful_basis: str = Field(
        "consent", examples=["consent"],
        description='"consent" or "legitimate_interest".')

    @field_validator("lawful_basis", mode="before")
    @classmethod
    def _known_basis(cls, v):
        if v is None or v == "":
            return "consent"
        if isinstance(v, str):
            v = v.strip().lower()
            if v in ("consent", "legitimate_interest"):
                return v
        raise ValueError(
            'lawful_basis must be "consent" or "legitimate_interest", not %r' % (v,))

    @model_validator(mode="after")
    def _basis_and_auth_agree(self):
        """A policy must not claim an authentication it will never ask for.

        Under legitimate_interest there is no consent screen and no subject to
        put in front of one, so required_auth_method could only ever be
        decoration - and a policy that reads "requires an OTP" while never
        asking for one is worse than no record at all.
        """
        if self.lawful_basis != "consent" and self.required_auth_method:
            raise ValueError(
                'required_auth_method must be null when lawful_basis is '
                '"%s": there is no consent screen to present it on'
                % self.lawful_basis)
        return self

    @field_validator("required_auth_method", mode="before")
    @classmethod
    def _known_auth_method(cls, v):
        """Reject anything but "otp"/null instead of storing it.

        Every check tests ``== "otp"``, so an unrecognised value - "OTP", "sms", a
        stray space - would read as "no authentication required" and quietly
        remove a factor. A policy field that disables a control when it is
        misspelled has to fail loudly, so the empty string and case are
        normalised and everything else is an error.
        """
        if v is None:
            return None
        if isinstance(v, str):
            v = v.strip().lower()
            if v in ("", "none", "null"):
                return None
            if v == "otp":
                return "otp"
        raise ValueError(
            'required_auth_method must be "otp" or null, not %r' % (v,))


class PolicyResponse(PolicyUpsert):
    model_config = ConfigDict(from_attributes=True)

    id: str
    partner_id: str
    version: int
    status: str  # pending | active | superseded | rejected
    awe_request_id: Optional[str] = None
    effective_from: Optional[datetime] = None

    @model_validator(mode="after")
    def _basis_and_auth_agree(self):
        """Report a stored policy as it is enforced; never refuse to read it.

        The upsert's rule stops a bad combination from being WRITTEN. Applied
        to a row already in the table it made the whole policy list a 500, so
        one legacy row hid every version of that partner's policy. Under a
        non-consent basis no subject is asked anything, so nothing reads
        required_auth_method and null is what is actually in force - and what
        this reports. The startup migration
        clears the column itself.
        """
        if self.lawful_basis != "consent" and self.required_auth_method:
            self.required_auth_method = None
        return self
