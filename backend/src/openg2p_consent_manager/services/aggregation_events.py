"""Consent events for the Aggregation Layer.

    consent_request.approved   {"consent_request_id": "..."}
    consent.withdrawn          {"consent_id": "...", "partner_id": "...",
                                "subject_id": {"type": "...", "value": "..."}}

POSTed to ``aggregation_layer_events_url`` with
``X-CM-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<raw body>">``.

Delivery runs in a background task with a few retries, so an approval or a
withdrawal never waits on - or fails because of - the Aggregation Layer. The
receiver is idempotent, so a retry after a lost response is harmless. An event
that exhausts its attempts is logged at ERROR with its full body, which is what
an operator replays it from.
"""
import asyncio
import hashlib
import hmac
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

import httpx

from ..config import Settings

_config = Settings.get_config()
_logger = logging.getLogger(_config.logging_default_logger_name)

EVENT_APPROVED = "consent_request.approved"
EVENT_WITHDRAWN = "consent.withdrawn"

# Strong references: a task with none can be garbage-collected mid-flight.
_pending: set = set()


def publish(event_type: str, data: Dict[str, Any]) -> None:
    """Queue one event. Returns at once; a no-op when no URL is configured."""
    if not _config.aggregation_layer_events_url:
        return
    event = {
        "event_id": str(uuid.uuid4()),
        "type": event_type,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    task = asyncio.create_task(_deliver(event))
    _pending.add(task)
    task.add_done_callback(_pending.discard)


def _signature(body: bytes) -> str:
    ts = str(int(time.time()))
    mac = hmac.new(_config.aggregation_layer_events_hmac_secret.encode("utf-8"),
                   ts.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()
    return "t=%s,v1=%s" % (ts, mac)


async def _deliver(event: Dict[str, Any]) -> None:
    body = json.dumps(event, separators=(",", ":")).encode("utf-8")
    attempts = max(1, _config.aggregation_layer_events_attempts)
    last = None
    for attempt in range(1, attempts + 1):
        headers = {"Content-Type": "application/json"}
        if _config.aggregation_layer_events_hmac_secret:
            # Re-signed per attempt: the receiver bounds the timestamp's age.
            headers["X-CM-Signature"] = _signature(body)
        try:
            async with httpx.AsyncClient(
                    timeout=_config.aggregation_layer_events_timeout) as client:
                response = await client.post(
                    _config.aggregation_layer_events_url, content=body, headers=headers)
            if 200 <= response.status_code < 300:
                _logger.info("Aggregation Layer event %s (%s) delivered",
                             event["event_id"], event["type"])
                return
            last = "HTTP %s" % response.status_code
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
        if attempt < attempts:
            await asyncio.sleep(5 ** (attempt - 1))
    _logger.error("Aggregation Layer event %s (%s) NOT delivered after %d attempt(s): "
                  "%s. Replay body: %s", event["event_id"], event["type"],
                  attempts, last, body.decode("utf-8"))
