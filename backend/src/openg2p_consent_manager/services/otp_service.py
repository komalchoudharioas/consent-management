"""One-time codes for the consent screen.

When a partner's policy sets ``required_auth_method = "otp"`` the subject must
prove, where they grant, that they hold the registered identity: ``approve``
refuses an AuthContext whose ``auth_method`` is anything else.

The mechanism itself lives in ``otp_provider``, chosen by config:

    otp_provider = fayda       Fayda's rules, in-process (default)
    otp_provider = internal    the same without the Fayda framing

This class is the seam the rest of the service talks to, so swapping backends
never reaches the lifecycle service or the controller.
"""
import logging

from openg2p_fastapi_common.service import BaseService

from ..config import Settings
from .otp_provider import OtpError, OtpProvider, build_otp_provider

_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)

__all__ = ["OtpService", "OtpError", "OtpProvider"]


class OtpService(BaseService):
    def __init__(self, name="", **kwargs):
        super().__init__(name if name else "OtpService", **kwargs)
        self._provider: OtpProvider = build_otp_provider()

    @property
    def provider_name(self) -> str:
        return getattr(self._provider, "name", "unknown")

    def set_provider(self, provider: OtpProvider) -> None:
        """Override the configured backend. For tests and for a deployment that
        supplies its own IDA client at startup."""
        self._provider = provider
        _logger.info("OTP provider overridden to '%s'", self.provider_name)

    async def issue(self, request, destination: str) -> None:
        """Ask the provider for a code and stamp the request with its state."""
        await self._provider.issue(request, destination)

    async def verify(self, request, code: str) -> None:
        """Raise OtpError unless the code is the live one for this request.

        Mutates ``otp_attempts`` on failure and sets ``otp_verified_at`` on
        success; the caller commits.
        """
        await self._provider.verify(request, code)

    def attempts_exhausted(self, request) -> bool:
        return (request.otp_attempts or 0) >= _config.otp_max_attempts
