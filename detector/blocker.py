"""
blocker.py — iptables-based IP banning.

When AnomalyDetector flags an IP it calls Blocker.ban().  We:
  1. Add an iptables DROP rule for the IP.
  2. Record the ban in self._bans with its timestamp and ban-level index.
  3. Send a Slack notification via SlackNotifier.
  4. Write an audit-log entry.

The Unbanner consults self._bans periodically to decide when to lift bans.

iptables notes
──────────────
• We use subprocess to call the real iptables binary.
• The `enabled` flag in config lets you test on machines without root
  or CAP_NET_ADMIN (it logs what it *would* do instead of running it).
• We check for duplicate rules before inserting to keep the chain clean.
"""

import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

log = logging.getLogger("blocker")


@dataclass
class BanRecord:
    ip: str
    banned_at: float
    condition: str
    rate: float
    baseline: float
    ban_level: int = 0          # index into unban schedule
    unban_at: Optional[float] = None  # None = permanent


class Blocker:
    """Manages iptables DROP rules and ban state."""

    def __init__(self, cfg: dict, notifier) -> None:
        self._lock = threading.Lock()
        self._chain: str = cfg["iptables"]["chain"]
        self._enabled: bool = cfg["iptables"]["enabled"]
        self._audit_path: str = cfg["audit"]["path"]
        self.notifier = notifier

        # ip → BanRecord
        self._bans: Dict[str, BanRecord] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def ban(self, ip: str, condition: str, rate: float, baseline: float) -> None:
        """
        Add an iptables DROP rule and record the ban.
        Called from a worker thread — must be thread-safe.
        """
        with self._lock:
            if ip in self._bans:
                log.debug("IP %s is already banned — skipping duplicate", ip)
                return

            record = BanRecord(
                ip=ip,
                banned_at=time.time(),
                condition=condition,
                rate=rate,
                baseline=baseline,
                ban_level=0,
            )
            self._bans[ip] = record

        self._iptables_drop(ip)
        self._audit("BAN", ip, condition, rate, baseline, duration="10m")
        self.notifier.ban_alert(ip, condition, rate, baseline, ban_duration="10 minutes")
        log.warning("Banned %s  condition=%s  rate=%.2f  baseline=%.2f", ip, condition, rate, baseline)

    def unban(self, ip: str) -> Optional[BanRecord]:
        """
        Remove the iptables DROP rule and return the BanRecord (or None if
        the IP wasn't banned).
        """
        with self._lock:
            record = self._bans.pop(ip, None)
        if record is None:
            return None

        self._iptables_remove(ip)
        log.info("Unbanned %s  ban_level_was=%d", ip, record.ban_level)
        return record

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            return ip in self._bans

    def get_bans(self) -> Dict[str, BanRecord]:
        """Return a shallow copy of the current bans dict (for dashboard/unbanner)."""
        with self._lock:
            return dict(self._bans)

    def update_ban_level(self, ip: str, new_level: int, unban_at: Optional[float]) -> None:
        with self._lock:
            if ip in self._bans:
                self._bans[ip].ban_level = new_level
                self._bans[ip].unban_at = unban_at

    # ── iptables helpers ──────────────────────────────────────────────────────

    def _iptables_drop(self, ip: str) -> None:
        cmd = ["iptables", "-I", self._chain, "1", "-s", ip, "-j", "DROP"]
        self._run(cmd, f"Block {ip}")

    def _iptables_remove(self, ip: str) -> None:
        cmd = ["iptables", "-D", self._chain, "-s", ip, "-j", "DROP"]
        self._run(cmd, f"Unblock {ip}")

    def _run(self, cmd: list, description: str) -> None:
        if not self._enabled:
            log.info("[DRY-RUN] %s: %s", description, " ".join(cmd))
            return
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                log.error("iptables error (%s): %s", description, result.stderr.strip())
            else:
                log.info("iptables OK: %s", description)
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            log.error("iptables failed (%s): %s", description, exc)

    # ── Audit log ─────────────────────────────────────────────────────────────

    def _audit(
        self,
        action: str,
        ip: str,
        condition: str,
        rate: float,
        baseline: float,
        duration: str = "",
    ) -> None:
        os.makedirs(os.path.dirname(self._audit_path), exist_ok=True)
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line = (
            f"[{ts}] {action} {ip} | condition={condition} | "
            f"rate={rate:.3f} | baseline={baseline:.3f} | duration={duration}\n"
        )
        try:
            with open(self._audit_path, "a") as fh:
                fh.write(line)
        except OSError as exc:
            log.warning("Audit log write failed: %s", exc)
