"""Healthchecks.io pings. Never raises: alerting must not break the run."""

import logging

from . import httpclient

log = logging.getLogger(__name__)

MAX_BODY = 100_000  # Healthchecks stores up to 100 KB per ping


class Healthchecks:
    def __init__(self, ping_url, timeout=10):
        self.url = ping_url.rstrip("/") if ping_url else ""
        self.timeout = timeout

    def success(self, message=""):
        self._ping("", message)

    def fail(self, message=""):
        """Marks the check down immediately and alerts."""
        self._ping("/fail", message)

    def log(self, message):
        """Record an event without changing the check's state."""
        self._ping("/log", message)

    def _ping(self, suffix, message=""):
        if not self.url:
            return
        try:
            httpclient.request("POST", f"{self.url}{suffix}",
                               data=message.encode()[:MAX_BODY], timeout=self.timeout,
                               retries=2, label=f"healthchecks{suffix or '/success'}")
        except httpclient.HTTPError as e:
            log.error("Healthchecks ping failed: %s", e)
