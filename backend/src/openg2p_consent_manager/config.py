from openg2p_fastapi_common.config import Settings as BaseSettings
from pydantic_settings import SettingsConfigDict

from . import __version__


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="consent_manager_", env_file=".env", extra="allow"
    )

    # Which API audience this instance serves — the platform's 4-API pattern
    # (staff / partner / beneficiary / agent). One image, one deployable per
    # audience; each mounts only its controllers and uses its own auth:
    #   staff       — Keycloak (staff realm): policy bindings, approvals, decisions
    #   partner     — PM keys (no Keycloak): the PDP /validate, status, receipts, JWKS
    #   beneficiary — Keycloak (beneficiary realm): /my/* + origination (deferred)
    #   all         — everything in one process (dev / back-compat default)
    api_audience: str = "all"

    openapi_title: str = "OpenG2P Consent Manager"
    openapi_description: str = """
        Consent Manager for OpenG2P.

        Acts as the Policy Decision Point (PDP) for outbound data sharing: it
        verifies partner-signed consent objects against each partner's onboarded
        policy and returns the effective set of fields a data holder (PEP) may
        release. Also issues canonical consent artefacts and signed receipts.
        """
    openapi_version: str = __version__

    # ── Database ────────────────────────────────────────────────────────────
    db_driver: str = "postgresql+asyncpg"
    db_username: str = "postgres"
    db_password: str = "postgres"
    db_hostname: str = "localhost"
    db_port: int = 5432
    db_dbname: str = "consent_manager_db"

    # Pooling is handled by openg2p-fastapi-common's async engine. For horizontal
    # scaling the app is fully stateless: scale by adding pods/workers and ensure
    # Postgres max_connections ≳ (pods × workers × pool_size + headroom).

    # ── Signing / trust ─────────────────────────────────────────────────────
    # CM receipt signing key. Preferred source is a PKCS#12 (.p12) keystore
    # holding the private key (+ certificate). Falls back to a PEM string, then
    # to a process-local ephemeral key (dev only). The signing algorithm is
    # auto-detected from the loaded key type (Ed25519→EdDSA, EC→ES256, RSA→RS256).
    cm_signing_p12_path: str = ""
    cm_signing_p12_password: str = ""
    cm_signing_private_key_pem: str = ""
    cm_signing_kid: str = "cm-2025-01"
    cm_signing_algorithm: str = "EdDSA"  # fallback hint only; key type wins
    # Set true by the Helm chart in demo mode so the service warns loudly that it
    # is signing with the public bundled demo key (must be replaced for production).
    cm_signing_is_demo: bool = False

    # NOTE: the data controller / module is a per-partner attribute
    # (Partner.controller_id), set at onboarding — one shared CM serves many
    # modules. A consent object's data_controller is validated against the
    # onboarded partner's controller_id, so there is no single global controller.

    # Replay window for embedded consent objects (seconds). issued_at must be
    # within now ± this skew.
    replay_freshness_window_sec: int = 300

    # ── Subject-granted consent in the hot path (gap B8) ────────────────────
    # Without this an approved consent authorises nothing: /validate matches
    # artefacts only by object_jti, and an originated artefact has none. When
    # enabled, an ACTIVE originated artefact for the same (partner, subject)
    # narrows the decision to what the subject actually granted, and links the
    # fetch to the subject's auth context.
    subject_consent_enabled: bool = True
    # Strict mode: deny when the subject has granted nothing. Off by default so
    # the partner-signed path keeps behaving exactly as before.
    subject_consent_required: bool = False

    # ── OIDC (origination flow ID-token validation) ─────────────────────────
    # If oidc_jwks_url is set, ID tokens are signature-verified against the IdP
    # JWKS. Otherwise claims are read unverified (dev only) and token_validated
    # is recorded as false.
    oidc_jwks_url: str = ""
    oidc_issuer: str = ""
    oidc_audience: str = ""

    # ── Hot-path caching (pod-local, TTL) ───────────────────────────────────
    # The partner row + its active policy change rarely but are read on every
    # validate. Cached in-process per pod; staleness bounded by the TTL. (Keys
    # are NOT part of this — they live in Partner Management, see below.)
    partner_cache_ttl_sec: int = 60
    partner_cache_enabled: bool = True

    # ── Partner public keys (Partner Management service) ────────────────────
    # Partner signing keys are no longer stored in CM. They are owned by the
    # Partner Management (PM) service and fetched from its unauthenticated
    # key-fetch API: GET {partner_mgmt_api_url}/keys/{reference_id}. CM caches
    # them per pod with the discipline PM's Cache-Control implies. A partner's
    # PM reference is Partner.partner_mgmt_id (falling back to Partner.audience).
    #
    # Empty partner_mgmt_api_url disables PM fetching — verification then fails
    # closed (no keys → deny), which is the correct safe default until wired.
    partner_mgmt_api_url: str = ""  # e.g. http://commons-services-pm-partner-api
    # Crypto backend for verifying the partner's signed consent object (a compact
    # JWS). "partner-mgmt" verifies against keys fetched from PM via the shared
    # openg2p-fastapi-common CryptoHelper. "keymanager" (Mosip) and "local"
    # (seed keys, tests) remain selectable but are not the default.
    crypto_backend: str = "partner-mgmt"
    # Algorithms accepted on the partner consent JWS. The fastapi-common default
    # is "RS256" only; partners commonly use EdDSA/ES256, so widen it here.
    crypto_allowed_algorithms: str = "EdDSA,ES256,RS256"
    # Soft TTL: refresh window. Bounds how long a rotated/revoked key stays
    # trusted. Capped by the response's Cache-Control max-age when smaller.
    partner_key_cache_ttl_seconds: int = 300
    # Hard TTL: during a PM outage, serve last-known-good keys up to this age,
    # then fail closed.
    partner_key_hard_ttl_seconds: int = 21600
    # Negative cache: remember a 404 ("no keys") briefly to avoid hammering PM
    # for a disabled/unknown partner on every request.
    partner_key_negative_ttl_seconds: int = 30
    # Minimum interval between forced refetches for one partner (throttles the
    # unknown-kid refresh that catches key rotation immediately).
    partner_key_refresh_cooldown_seconds: int = 10
    # HTTP timeout (seconds) for a single key fetch from PM.
    partner_key_fetch_timeout_seconds: float = 3.0

    # ── Caller authentication (Keycloak / OIDC bearer) ──────────────────────
    # Validates bearer tokens on protected endpoints against the Keycloak JWKS,
    # exactly like the AWE service. When auth_enabled is false (dev), tokens are
    # accepted without verification and role checks pass.
    auth_enabled: bool = True
    auth_issuer: str = ""  # e.g. https://keycloak.../realms/staff
    auth_jwks_url: str = ""  # usually issuer + /protocol/openid-connect/certs
    auth_audience: str = ""  # optional; empty disables the audience check
    auth_algorithms: list[str] = ["RS256", "ES256", "EdDSA"]
    # Role (realm- or client-scoped) required for partner/policy admin endpoints.
    auth_admin_role: str = "CONSENT_MANAGER_ADMIN"
    # Default subject id-type when a token omits the subject_id_type claim.
    subject_default_id_type: str = "national_id"

    # Role required to act on AWE approval tasks via CM's proxy/inbox. Approvers
    # log into CM (not AWE) and CM proxies task-list/decision calls to AWE with
    # the approver's own JWT.
    auth_approver_role: str = "CONSENT_MANAGER_APPROVER"

    # ── Approval Workflow Engine (AWE) integration ──────────────────────────
    # Widening a partner's data-share POLICY is gated behind human approval in the
    # shared, per-environment AWE. CM is a *caller service*: on a widening it
    # submits an approval request and keeps the new policy version `pending`,
    # flipping it `active` only when AWE delivers a terminal `request_approved`
    # webhook. Approvers act in CM's OWN UI — CM proxies AWE's task-list/decision
    # endpoints with the approver's JWT (AWE has no approver UI, only /admin).
    #
    # When awe_enabled is false (default), a widening policy activates immediately
    # (no approval gate) — legacy behaviour.
    awe_enabled: bool = False
    # Base URL of the environment's AWE, reachable from CM pods (e.g.
    # https://awe.<baseDomain>). No trailing slash needed.
    awe_base_url: str = ""
    awe_http_timeout_seconds: float = 30.0
    # AWE approval policy (workflow: stages/approvers/SLA) that governs data-share
    # policy changes. Registered in AWE out-of-band. NB: distinct from CM's own
    # data-share policy — this is the *approval* policy key.
    awe_policy_change_policy_key: str = "consent-manager.policy_change.v1"
    # CM→AWE service auth: Keycloak client-credentials. The fetched bearer is
    # sent on POST /v1/awe/requests. If awe_static_token is set it is used
    # verbatim instead (dev/testing).
    awe_token_url: str = ""  # Keycloak token endpoint
    awe_client_id: str = ""
    awe_client_secret: str = ""
    awe_static_token: str = ""
    # Per-caller callback secret CM registered into the shared AWE DB. AWE looks
    # the raw secret up by this id; CM holds the same raw secret to verify the
    # HMAC on inbound webhooks. `callback_secret_id` is passed on every request.
    awe_callback_secret_id: str = ""
    awe_callback_hmac_secret: str = ""
    # Public URL AWE should POST terminal webhooks back to. Must resolve to
    # CM's /consent/v1/awe/webhooks/decision endpoint.
    awe_callback_url: str = ""
    # Reject webhooks whose signed timestamp is more than this far from now.
    awe_webhook_max_skew_sec: int = 300

    # ── OTP (the subject's authentication on the consent screen) ───────────
    otp_length: int = 6
    otp_ttl_sec: int = 300
    otp_max_attempts: int = 3
    # Mixed into the OTP hash so a stolen database row cannot be brute-forced
    # against a 6-digit space offline. Set this per environment.
    otp_salt: str = "change-me-per-environment"
    # DEV ONLY. Exposes GET /consent/v1/consent-requests/{id}/otp. There is no
    # SMS or email gateway in this stack, so the default sender logs the code;
    # this endpoint reports the OTP state alongside it.
    otp_debug_enabled: bool = False

    # Which OTP backend to use. "fayda" applies Fayda's rules in-process via
    # utils/fayda_otp; "internal" is the same without the Fayda framing.
    # Switching is config only - nothing above services/otp_provider.py changes,
    # which is also how a real Fayda deployment would plug in.
    otp_provider: str = "fayda"
    # ── OTP publishing (S3 / MinIO drop box) ──────────────────────
    # Mirrors the OAN Gen 1 / A2C arrangement: each issued OTP is written to a
    # bucket under otp/ so a tester can read it without an SMS gateway. DEV
    # ONLY - anything that can read the bucket reads a live OTP beside the
    # individual it belongs to. Off by default; see services/otp_publisher.py.
    otp_publish_enabled: bool = False
    otp_publish_bucket: str = "a2c-webhook"
    otp_publish_prefix: str = "otp/"
    otp_publish_region: str = "ap-south-1"
    # Set to point at MinIO or any S3-compatible store; empty resolves AWS.
    otp_publish_endpoint_url: str = ""
    otp_publish_access_key: str = ""
    otp_publish_secret_key: str = ""

    # ── Fayda (OAN mock, g2p_ati_consent_mgt/utils/mock_fayda_otp_api.py) ───
    # Base URL with no path: the endpoints are /requestData and /getDataAuth.
    fayda_base_url: str = ""
    fayda_client_id: str = "demo-client"
    fayda_client_secret: str = "demo-secret"
    fayda_version: str = "1.0"
    # env and domain_uri must match the server's own MOCK_FAYDA_ENV and
    # MOCK_FAYDA_DOMAIN_URI exactly, or it answers 400 before anything else.
    fayda_env: str = "prod"
    fayda_domain_uri: str = "fayda.et"
    fayda_identifier_type: str = "FIN"
    fayda_otp_channel: str = "PHONE"
    # Only used to render the masked-mobile line in the log, so an
    # operator can see WHERE a real Fayda would have sent the code.
    fayda_demo_phone: str = "0911000055"
    fayda_timeout: float = 20.0
    # Fayda keys on the individual's Fayda/FIN number, not a Keycloak username,
    # so a demo subject has to be mapped onto one.
    # JSON: {"staff": "6140798523698702"}
    fayda_individual_id_map: str = ""

    @property
    def fayda_individual_ids(self) -> dict:
        import json
        import logging

        raw = (self.fayda_individual_id_map or "").strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except Exception as exc:  # noqa: BLE001
            logging.getLogger(self.logging_default_logger_name).error(
                "fayda_individual_id_map is not valid JSON (%s); subjects will "
                "be passed through unmapped", exc)
            return {}
        return parsed if isinstance(parsed, dict) else {}
