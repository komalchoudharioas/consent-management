# ruff: noqa: E402
import asyncio
import logging

from .config import Settings

_config = Settings.get_config()

from openg2p_fastapi_common.app import Initializer as BaseInitializer

from .controllers import (
    AggregationLayerController,
    AggregatorController,
    AweController,
    DecisionsController,
    LifecycleController,
    PartnerController,
    SubjectController,
    VerificationController,
    WellKnownController,
)
from .models import (
    AggregationRequest,
    AuditLog,
    AuthContext,
    AweProcessedEvent,
    ConsentArtefact,
    ConsentReceipt,
    ConsentRequest,
    DecisionLog,
    Partner,
    PartnerPolicy,
    RevocationRecord,
)
from .services import (
    OtpPublisher,
    AggregationLayerService,
    AggregatorService,
    AweClient,
    AweWebhookService,
    ConsentService,
    CryptoService,
    LifecycleService,
    OtpService,
    PartnerService,
    PolicyService,
    ReceiptService,
    RegistryClient,
    VerificationService,
)

_logger = logging.getLogger(_config.logging_default_logger_name)


class Initializer(BaseInitializer):
    def initialize(self, **kwargs):
        super().initialize(**kwargs)

        # Services — order matters: a service that calls get_component() in its
        # __init__ must be constructed after its dependencies.
        CryptoService()
        PartnerService()
        PolicyService()
        ReceiptService()
        VerificationService()
        ConsentService()
        LifecycleService()
        AweClient()
        AweWebhookService()  # depends on PartnerService
        OtpPublisher()   # no-op unless otp_publish_enabled
        OtpService()
        RegistryClient()   # depends on CryptoService
        AggregatorService()  # depends on Verification, Registry, Otp, Crypto
        AggregationLayerService()

        # Controllers — mounted per API audience (the platform's 4-API pattern).
        # One image, one deployable per audience; each mounts only its routes.
        audience = _config.api_audience
        staff = audience in ("staff", "all")
        partner = audience in ("partner", "all")
        beneficiary = audience in ("beneficiary", "all")
        _logger.info("Consent Manager API audience: %s", audience)

        if partner:
            # PARTNER api — PDP. Trust = partner-signed consent object (PM keys),
            # no Keycloak. Serves /validate, status, receipts, JWKS.
            VerificationController().post_init()
            WellKnownController().post_init()
            # Service APIs for the external Aggregation Layer (service role).
            AggregationLayerController().post_init()
            if _config.aggregator_enabled:
                AggregatorController().post_init()
        if staff:
            # STAFF api — Keycloak staff realm. Policy admin, approvals, decisions.
            PartnerController().post_init()
            AweController().post_init()
            DecisionsController().post_init()
        if beneficiary:
            # BENEFICIARY api — Keycloak beneficiary realm. /my/* + origination.
            SubjectController().post_init()
            LifecycleController().post_init()

    # ── the aggregation queue ───────────────────────────────────────────────
    #
    # These are the platform's lifespan hooks, called from the base
    # Initializer's ``fastapi_app_lifespan``. They are the only ones that fire:
    # because that lifespan is passed to FastAPI explicitly, Starlette ignores
    # any ``@app.on_event`` handler registered alongside it — silently, with
    # nothing in the log to say the handler was dropped.
    #
    # With ``kafka_consumers_in_app`` the API process also consumes, which is
    # the single-process development shape and matches how the platform's Audit
    # Manager runs producer and consumer in one service. In production set it
    # false and run ``python -m openg2p_consent_manager.worker``: the point of
    # moving the fan-out off the request path is lost if the registry queries
    # still share an event loop with the portal serving the subject.

    async def fastapi_app_startup(self, app):
        await super().fastapi_app_startup(app)
        if not _config.kafka_enabled:
            return
        from .kafka_bus.bus import bus

        await bus.start()
        if _config.kafka_consumers_in_app:
            from .kafka_bus.consumers import runner

            await runner.start()
        else:
            _logger.info("kafka_consumers_in_app=false - this process publishes "
                         "only; run `python -m openg2p_consent_manager.worker`")

    async def fastapi_app_shutdown(self, app):
        if _config.kafka_enabled:
            from .kafka_bus.bus import bus
            from .kafka_bus.consumers import runner

            if _config.kafka_consumers_in_app:
                await runner.stop()
            await bus.stop()
        await super().fastapi_app_shutdown(app)

    def migrate_database(self, args):
        super().migrate_database(args)

        async def migrate():
            _logger.info("Migrating consent manager database")
            for model in (
                Partner,
                PartnerPolicy,
                ConsentRequest,
                AuthContext,
                ConsentArtefact,
                ConsentReceipt,
                RevocationRecord,
                DecisionLog,
                AuditLog,
                AweProcessedEvent,
                AggregationRequest,
            ):
                await model.create_migrate()

            # create_migrate() only creates missing tables; it does not ALTER an
            # existing one. Apply idempotent column changes so a DB created under
            # an earlier schema picks up the current shape on next migrate.
            from openg2p_fastapi_common.context import dbengine
            from sqlalchemy import text

            async with dbengine.get().begin() as conn:
                # Partner is now a policy binding: keys + identity live in Partner
                # Management. Carry a PM reference; identity/onboarding fields go.
                await conn.execute(
                    text(
                        "ALTER TABLE partners ADD COLUMN IF NOT EXISTS "
                        "partner_mgmt_id VARCHAR(255)"
                    )
                )
                await conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS ix_partners_partner_mgmt_id "
                        "ON partners (partner_mgmt_id)"
                    )
                )
                # name is now an optional display label; org_name + the old
                # partner-onboarding approval columns are gone (approval moved
                # onto the policy version).
                await conn.execute(text("ALTER TABLE partners ALTER COLUMN name DROP NOT NULL"))
                await conn.execute(text("ALTER TABLE partners DROP COLUMN IF EXISTS org_name"))
                await conn.execute(text("ALTER TABLE partners DROP COLUMN IF EXISTS approval_status"))
                await conn.execute(text("ALTER TABLE partners DROP COLUMN IF EXISTS awe_request_id"))
                # AWE approval now correlates to a policy version.
                await conn.execute(
                    text(
                        "ALTER TABLE partner_policies ADD COLUMN IF NOT EXISTS "
                        "awe_request_id VARCHAR(64)"
                    )
                )
                await conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS ix_partner_policies_awe_request_id "
                        "ON partner_policies (awe_request_id)"
                    )
                )
                # The OTP backend became pluggable after the table was first
                # created, so carry the two columns onto an existing database.
                await conn.execute(
                    text(
                        "ALTER TABLE aggregation_requests ADD COLUMN IF NOT EXISTS "
                        "otp_provider VARCHAR(50)"
                    )
                )
                await conn.execute(
                    text(
                        "ALTER TABLE aggregation_requests ADD COLUMN IF NOT EXISTS "
                        "otp_reference VARCHAR(255)"
                    )
                )
                await conn.execute(
                    text(
                        "ALTER TABLE aggregation_requests ADD COLUMN IF NOT EXISTS "
                        "otp_debug_code VARCHAR(16)"
                    )
                )
                # The OTP moved onto the consent screen: the subject authenticates
                # once, where they grant, instead of once there and again at the
                # fetch. consent_requests therefore carries the same otp_* shape
                # aggregation_requests does, and an aggregation that had to raise
                # a consent request points at it.
                for column, ddl in (
                    ("otp_hash", "VARCHAR(128)"),
                    ("otp_expires_at", "TIMESTAMPTZ"),
                    ("otp_attempts", "INTEGER DEFAULT 0"),
                    ("otp_verified_at", "TIMESTAMPTZ"),
                    ("otp_channel", "VARCHAR(50)"),
                    ("otp_destination", "VARCHAR(255)"),
                    ("otp_provider", "VARCHAR(50)"),
                    ("otp_reference", "VARCHAR(255)"),
                    ("otp_debug_code", "VARCHAR(16)"),
                ):
                    await conn.execute(
                        text(
                            "ALTER TABLE consent_requests ADD COLUMN IF NOT EXISTS "
                            "%s %s" % (column, ddl)
                        )
                    )
                await conn.execute(
                    text(
                        "ALTER TABLE aggregation_requests ADD COLUMN IF NOT EXISTS "
                        "consent_request_id VARCHAR"
                    )
                )
                await conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS "
                        "ix_aggregation_requests_consent_request_id "
                        "ON aggregation_requests (consent_request_id)"
                    )
                )
                # Which authentication a partner's subjects must perform.
                #
                # The fetch-time OTP used to be unconditional, so every policy
                # written before it became a policy decision means "otp" even
                # though the column is NULL. Backfilling is what keeps this
                # change from silently dropping a factor for existing partners.
                #
                # It must happen EXACTLY ONCE, when the column is introduced —
                # hence the DO block rather than an unconditional UPDATE. NULL
                # is a legitimate, deliberate value here: it is how an operator
                # says "this partner needs no code". An UPDATE ... WHERE
                # required_auth_method IS NULL re-runs on every startup and
                # silently re-arms the factor they turned off, which reads as
                # the setting not sticking. (It did: every active policy had
                # been forced back to 'otp'.)
                await conn.execute(
                    text(
                        "DO $$ BEGIN "
                        "  IF NOT EXISTS (SELECT 1 FROM information_schema.columns "
                        "                 WHERE table_name = 'partner_policies' "
                        "                   AND column_name = 'required_auth_method') "
                        "  THEN "
                        "    ALTER TABLE partner_policies ADD COLUMN required_auth_method VARCHAR(20); "
                        "    UPDATE partner_policies SET required_auth_method = 'otp' "
                        "     WHERE status = 'active'; "
                        "  END IF; "
                        "END $$;"
                    )
                )
                await conn.execute(
                    text(
                        "ALTER TABLE aggregation_requests ADD COLUMN IF NOT EXISTS "
                        "otp_required BOOLEAN NOT NULL DEFAULT TRUE"
                    )
                )
                # Why a partner may hold the data. Every policy written before
                # this one required a subject grant, so "consent" is both the
                # default and the correct backfill - the column is NOT NULL so
                # that a basis can never be absent from the record.
                for _table in ("partner_policies", "aggregation_requests"):
                    await conn.execute(
                        text(
                            "ALTER TABLE %s ADD COLUMN IF NOT EXISTS "
                            "lawful_basis VARCHAR(40) NOT NULL DEFAULT 'consent'"
                            % _table
                        )
                    )
                # A policy under a non-consent basis must carry no auth method
                # (PolicyUpsert refuses it). Rows written before that rule -
                # some re-armed to 'otp' by the old IS NULL backfill above -
                # still did. Unlike that backfill this is safe to re-run on
                # every start: it only ever CLEARS a value that nothing under
                # legitimate_interest reads, so it cannot change behaviour.
                await conn.execute(
                    text(
                        "UPDATE partner_policies SET required_auth_method = NULL "
                        " WHERE lawful_basis <> 'consent' "
                        "   AND required_auth_method IS NOT NULL"
                    )
                )
                # The fan-out and the callback moved onto Kafka topics, so a
                # row now records which worker holds it and how many times the
                # work has been started. Existing rows get the defaults, which
                # read correctly for work that has already finished.
                for column, ddl in (
                    ("fetch_attempts", "INTEGER NOT NULL DEFAULT 0"),
                    ("claimed_by", "VARCHAR(64)"),
                    ("claimed_at", "TIMESTAMPTZ"),
                    ("next_retry_at", "TIMESTAMPTZ"),
                ):
                    await conn.execute(
                        text(
                            "ALTER TABLE aggregation_requests ADD COLUMN IF NOT "
                            "EXISTS %s %s" % (column, ddl)
                        )
                    )
                # The reaper and the queue depth both filter on (status,
                # claimed_at); without this they sequentially scan the table.
                await conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS "
                        "ix_aggregation_requests_status_claimed_at "
                        "ON aggregation_requests (status, claimed_at)"
                    )
                )
            _logger.info("Database migration complete")

        asyncio.run(migrate())
