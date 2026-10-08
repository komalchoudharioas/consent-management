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

    # Role held by trusted platform services (the Aggregation Layer's Keycloak
    # client) on the service-to-service APIs: partner lookup, policy read,
    # recording a grant, reading what a consent request granted.
    auth_service_role: str = "CONSENT_MANAGER_SERVICE"

    # ── Aggregation Layer events ────────────────────────────────────────────
    # The Aggregation Layer runs as its own service. It learns that a consent
    # request it raised was approved, or that a consent was withdrawn, from
    # these events (POSTed, HMAC-signed). Empty URL sends nothing.
    aggregation_layer_events_url: str = ""  # e.g. http://aggregation-layer:8100/aggregation/v1/cm-events
    aggregation_layer_events_hmac_secret: str = ""
    aggregation_layer_events_timeout: float = 10.0
    # Attempts per event, spaced 1s, 5s, 25s ... An event that still fails is
    # logged; the approval or withdrawal itself is never rolled back.
    aggregation_layer_events_attempts: int = 4

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

    # ── Aggregator: async, OTP-gated, cross-registry fetch ──────────────────
    # One partner call naming fields from several registries, answered on a
    # callback once the subject has entered an OTP. The registries' own
    # /dci/registry/sync/search is untouched; the aggregator calls each of them
    # as an ordinary partner, so consent enforcement still applies per hop.
    aggregator_enabled: bool = True
    # Identity the aggregator signs its internal consent objects with. Its
    # public key must be registered in Partner Management and it needs a CM
    # binding per registry — see scripts/register-aggregator.py.
    aggregator_issuer: str = "cm-aggregator"
    # MUST map to the Partner Management partner holding the aggregator's public
    # key. The registry derives that reference from the DCI header as
    #   PARTNER_{sender_id.replace("-","_").upper()}
    # (keymanager_helper.partner_reference_id), so "cm-aggregator" resolves to
    # PARTNER_CM_AGGREGATOR. Change one without the other and every internal hop
    # fails with signature_invalid / REQUEST_VALIDATION_ERROR.
    aggregator_sender_id: str = "cm-aggregator"
    aggregator_purpose_code: str = "loan_origination"
    aggregator_consent_validity_sec: int = 300
    # A per-registry grant is reused, rather than minted again, only while at
    # least this much of its validity is left. A fan-out that retries must not
    # start on a grant that lapses under it, so this is well above one hop.
    aggregator_grant_reuse_min_remaining_sec: int = 150
    # When the subject has no consent for this partner, raise one for them and
    # park the aggregation until it is approved, instead of refusing the seek
    # with no_subject_consent. False restores the two-step behaviour where the
    # partner must obtain consent out of band before it may call.
    aggregator_raise_consent: bool = True
    # Where the subject's consent screen lives, used to build the consent_url
    # the partner redirects them to. Empty omits the field rather than guessing.
    consent_ui_base_url: str = "http://localhost:3002"
    aggregator_page_size: int = 10
    aggregator_registry_timeout: float = 30.0
    aggregator_callback_timeout: float = 30.0
    # reg_type/reg_record_type on the aggregated on-search. The record spans
    # registries, so neither can honestly be one registry's value.
    aggregator_reg_type: str = "spdci-extensions-dci:AggregatedRecord"
    aggregator_reg_record_type: str = "spdci-extensions-dci:AggregatedRecord"
    # Where each registry lives and which CM binding to spend there, as JSON:
    #   {"farmer": {"url": "...", "audience": "...", "controller_id": "...",
    #               "reg_type": "...", "reg_record_type": "...",
    #               "receiver_id": "...", "id_type": "functional_id"}}
    # Keys must match the registry prefixes used in services/field_catalog.py.
    aggregator_registries: str = ""

    # ── Kafka (the fan-out and delivery queues) ────────────────────────────
    #
    # Without a broker, verify_otp spawns asyncio.create_task() and the
    # registry fan-out runs inside the API worker that happened to serve the
    # request. Fifty subjects entering an OTP in the same minute means fifty
    # concurrent, unbounded fan-outs competing with the portal's own request
    # handling, and a partner whose callback is down loses the data outright:
    # one POST is attempted, and there is nothing to retry it.
    #
    # With a broker the HTTP handler only publishes, which is bounded and
    # fast. Workers consume at a rate the registries can survive, and delivery
    # is a separate topic so a slow partner cannot hold a registry worker.
    #
    # False keeps the in-process behaviour, so the demo stack runs unchanged
    # with no broker to start. See KAFKA.md.
    kafka_enabled: bool = False
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_client_id: str = "openg2p-consent-manager"
    # Topics are derived from this prefix unless named explicitly, following
    # the platform's Audit Manager convention (openg2p.audit.events/.dlq).
    kafka_topic_prefix: str = "openg2p.consent"
    kafka_topic_fanout: str = ""    # <prefix>.aggregation.fanout
    kafka_topic_delivery: str = ""  # <prefix>.aggregation.delivery
    # Base name only. The retry topics are one PER BACKOFF STEP, derived from
    # this and kafka_retry_backoff_seconds: <base>.10s, <base>.60s, and so on.
    # See the Settings.retry_tiers docstring for why a single one cannot work.
    kafka_topic_retry: str = ""     # <prefix>.aggregation.delivery.retry
    kafka_topic_dlq: str = ""       # <prefix>.aggregation.dlq
    kafka_group_fanout: str = "openg2p-consent-fanout"
    kafka_group_delivery: str = "openg2p-consent-delivery"
    # Base name; each tier gets "<base>-<delay>s" so their offsets stay
    # independent and a busy tier cannot hold up an idle one.
    kafka_group_retry: str = "openg2p-consent-retry"
    # Partitions cap how many fan-outs can run at once across the whole
    # deployment, so this is the load limit the registries actually feel.
    # 12 mirrors the Audit Manager default.
    kafka_topic_partitions: int = 12
    kafka_topic_replication: int = 1
    # Idempotent CREATE TOPICS on startup, like the Audit Manager's topicInit
    # Job. Harmless when the topics exist; set false where the broker forbids
    # client-side topic creation.
    kafka_topic_init: bool = True
    # The delivery topic carries the aggregated record itself, because
    # retrying a callback must not mean querying the registries a second time.
    # That is personal data at rest in Kafka for as long as the topic keeps
    # it, so the retention is deliberately short and set on creation.
    kafka_delivery_retention_ms: int = 3_600_000      # 1 hour
    kafka_dlq_retention_ms: int = 604_800_000         # 7 days
    # Run the consumers inside the API process. True is the single-process
    # dev default; in production run `python -m openg2p_consent_manager.worker`
    # and set this false, so registry fan-out cannot compete with the portal's
    # own event loop at all.
    kafka_consumers_in_app: bool = True
    # In-flight work per consumer. The ceiling on registry load is this times
    # the number of consumer instances, bounded by the partition count.
    kafka_fanout_concurrency: int = 4
    kafka_delivery_concurrency: int = 8
    # How long a publish may block the HTTP handler before it gives up and
    # falls back to an in-process task. The subject has already burnt their
    # OTP by this point; refusing the request would lose the authorisation.
    kafka_producer_timeout: float = 5.0
    # Callback retries. Attempt 1 is immediate; the rest are spaced by this
    # list, then the message goes to the DLQ.
    kafka_delivery_max_attempts: int = 5
    kafka_retry_backoff_seconds: str = "10,60,300,900"
    # A row left "fetching"/"delivering" by a worker that died is re-queued
    # after this long by `python -m openg2p_consent_manager.reap`.
    kafka_claim_timeout_sec: int = 600

    # ── OTP (subject's real-time authorisation for an aggregated fetch) ─────
    otp_length: int = 6
    otp_ttl_sec: int = 300
    otp_max_attempts: int = 3
    # Mixed into the OTP hash so a stolen database row cannot be brute-forced
    # against a 6-digit space offline. Set this per environment.
    otp_salt: str = "change-me-per-environment"
    # DEV ONLY. Exposes GET /consent/v1/aggregation/{id}/otp. There is no SMS or
    # email gateway in this stack, so the default sender logs the code; this
    # endpoint reports the OTP state alongside it.
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


    @property
    def aggregator_registry_map(self) -> dict:
        """``aggregator_registries`` parsed, with a safe empty default.

        A bad value must not take the whole service down at import time, so a
        parse failure logs and yields {} — the aggregator then reports
        'not_configured' per registry instead of 500ing.
        """
        import json
        import logging

        raw = (self.aggregator_registries or "").strip()
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except Exception as exc:  # noqa: BLE001
            logging.getLogger(self.logging_default_logger_name).error(
                "consent_manager_aggregator_registries is not valid JSON (%s); "
                "the aggregator will report every registry as not_configured", exc)
            return {}
        return parsed if isinstance(parsed, dict) else {}

    # ── Kafka derived values ────────────────────────────────────────────────
    #
    # Each topic name is overridable, but defaults to a suffix on the prefix so
    # a deployment only has to set one variable to namespace the whole service.

    def _topic(self, explicit: str, suffix: str) -> str:
        return (explicit or "").strip() or "%s.%s" % (
            self.kafka_topic_prefix.rstrip("."), suffix)

    @property
    def topic_fanout(self) -> str:
        """Work queue: one message per aggregation cleared to fetch."""
        return self._topic(self.kafka_topic_fanout, "aggregation.fanout")

    @property
    def topic_delivery(self) -> str:
        """Outbound queue: the signed on-search envelope, awaiting its callback."""
        return self._topic(self.kafka_topic_delivery, "aggregation.delivery")

    @property
    def topic_retry(self) -> str:
        """Base name for the retry tiers. Not itself consumed."""
        return self._topic(self.kafka_topic_retry, "aggregation.delivery.retry")

    @property
    def retry_tiers(self) -> list:
        """One topic per backoff step: ``...delivery.retry.10s``, ``.60s``, …

        A single retry topic cannot work, and the reason is worth writing down
        because it is not obvious until it bites. The wait has to live
        somewhere, and the simple answer is to sleep in the consumer — but a
        Kafka consumer is a **loop**: it does not fetch the next batch until
        the current one is done. Put a 900-second hold and a 10-second hold on
        the same topic and the 10-second one waits 900 seconds, because the
        consumer is still asleep on the message in front of it.

        Splitting by duration removes the problem rather than managing it:
        every message on a tier waits exactly the same length of time, so a
        message that arrived earlier is always due earlier, and first-in
        first-out is precisely the right order to process them in. The sleep
        blocks only messages that were going to wait that long anyway.

        Each tier gets its own consumer group, so their offsets are
        independent — a tier that is busy cannot hold up a tier that is idle.
        """
        return [{"delay": delay,
                 "topic": "%s.%ds" % (self.topic_retry, delay),
                 "group": "%s-%ds" % (self.kafka_group_retry, delay)}
                for delay in self.retry_backoff]

    def retry_tier_for(self, delay: int) -> str:
        """The tier topic a given backoff belongs on.

        An exact match normally; otherwise the nearest tier at or above it, so
        a hand-set delay is never rounded *down* into a shorter wait.
        """
        tiers = self.retry_tiers
        for tier in tiers:
            if tier["delay"] >= delay:
                return tier["topic"]
        return tiers[-1]["topic"]

    @property
    def topic_dlq(self) -> str:
        """Anything that exhausted its attempts, kept for an operator to look at."""
        return self._topic(self.kafka_topic_dlq, "aggregation.dlq")

    @property
    def retry_backoff(self) -> list:
        """``kafka_retry_backoff_seconds`` as a list of ints.

        A malformed value must not strand deliveries, so it falls back to the
        documented default rather than raising at import time.
        """
        import logging

        raw = (self.kafka_retry_backoff_seconds or "").strip()
        try:
            values = [int(part) for part in raw.split(",") if part.strip()]
        except ValueError:
            values = []
        if not values:
            logging.getLogger(self.logging_default_logger_name).error(
                "consent_manager_kafka_retry_backoff_seconds is not a list of "
                "integers (%r); using 10,60,300,900", raw)
            values = [10, 60, 300, 900]
        return values
