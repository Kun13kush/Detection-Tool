"""
notifier.py — Slack webhook notifications.

Sends three types of alerts:
  • ban_alert    — IP blocked (within 10 s of detection)
  • unban_alert  — IP released from ban
  • global_alert — global traffic anomaly (no block applied)

All alerts include: condition, current rate, baseline, timestamp,
and (for bans) the ban duration.
"""
import os
import json
import logging
import time
import urllib.request
import urllib.error

log = logging.getLogger("notifier")

# Emoji shortcuts for readability
_ICON_BAN = ":rotating_light:"
_ICON_UNBAN = ":white_check_mark:"
_ICON_GLOBAL = ":warning:"


class SlackNotifier:
    """Sends Slack messages via an incoming-webhook URL."""

    def __init__(self, cfg: dict) -> None:
        self._webhook: str = (
            os.environ.get("SLACK_WEBHOOK_URL")
            or cfg["slack"]["webhook_url"]
        )
        self._timeout: int = cfg["slack"]["timeout_seconds"]
    # ── Public alert methods ──────────────────────────────────────────────────

    def ban_alert(
        self,
        ip: str,
        condition: str,
        rate: float,
        baseline: float,
        ban_duration: str,
    ) -> None:
        ts = _now()
        text = (
            f"{_ICON_BAN} *IP BANNED* — `{ip}`\n"
            f"> *Condition:* `{condition}`\n"
            f"> *Rate:* `{rate:.2f} req/s`\n"
            f"> *Baseline:* `{baseline:.2f} req/s`\n"
            f"> *Ban Duration:* `{ban_duration}`\n"
            f"> *Time:* `{ts}`"
        )
        self._send(text)

    def unban_alert(
        self,
        ip: str,
        condition: str,
        rate: float,
        baseline: float,
        next_duration: str,
    ) -> None:
        ts = _now()
        text = (
            f"{_ICON_UNBAN} *IP UNBANNED* — `{ip}`\n"
            f"> *Original Condition:* `{condition}`\n"
            f"> *Was Rate:* `{rate:.2f} req/s`  *Baseline:* `{baseline:.2f} req/s`\n"
            f"> *Next violation duration:* `{next_duration}`\n"
            f"> *Time:* `{ts}`"
        )
        self._send(text)

    def global_alert(self, condition: str, rate: float, baseline: float) -> None:
        ts = _now()
        text = (
            f"{_ICON_GLOBAL} *GLOBAL TRAFFIC ANOMALY*\n"
            f"> *Condition:* `{condition}`\n"
            f"> *Global Rate:* `{rate:.2f} req/s`\n"
            f"> *Baseline:* `{baseline:.2f} req/s`\n"
            f"> *Action:* Alert only (no block applied)\n"
            f"> *Time:* `{ts}`"
        )
        self._send(text)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _send(self, text: str) -> None:
        """POST the message to Slack; log on failure but never crash."""
        if not self._webhook or "YOUR/WEBHOOK" in self._webhook:
            log.info("[SLACK-DRY-RUN] %s", text[:120])
            return

        payload = json.dumps({"text": text}).encode("utf-8")
        req = urllib.request.Request(
            self._webhook,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                if resp.status != 200:
                    log.error("Slack returned HTTP %d", resp.status)
                else:
                    log.debug("Slack alert sent OK")
        except urllib.error.URLError as exc:
            log.error("Slack webhook failed: %s", exc)
        except Exception as exc:  # noqa: BLE001
            log.error("Unexpected Slack error: %s", exc)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
