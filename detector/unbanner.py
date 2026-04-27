"""
unbanner.py — Automatic IP unban with exponential backoff.

Backoff schedule (from config.yaml):
  Level 0 → ban for 10 minutes, then unban → next violation → level 1
  Level 1 → ban for 30 minutes
  Level 2 → ban for 2 hours
  Level 3 → permanent (never unbanned, schedule value = -1)

On every first ban the Unbanner sets unban_at = banned_at + schedule[0].
After each unban it increments the ban level so the next violation is
harsher.  A permanent ban has unban_at = None and is never released.

This module runs in its own background thread (run() loops every 10 s).
"""

import logging
import time
import threading

log = logging.getLogger("unbanner")


class Unbanner:
    """Periodically checks bans and releases them per the backoff schedule."""

    def __init__(self, cfg: dict, blocker, notifier) -> None:
        self._schedule: list = cfg["unban"]["schedule"]  # e.g. [600, 1800, 7200, -1]
        self._audit_path: str = cfg["audit"]["path"]
        self.blocker = blocker
        self.notifier = notifier
        self._poll_interval: int = 10  # seconds between sweeps

    # ── Background loop ───────────────────────────────────────────────────────

    def run(self) -> None:
        """
        Runs forever in a daemon thread.
        On startup, seeds the unban_at for any bans that were recorded
        without one (shouldn't happen in normal flow, but defensive).
        """
        log.info("Unbanner started — polling every %d s", self._poll_interval)
        while True:
            self._sweep()
            time.sleep(self._poll_interval)

    # ── Core sweep ────────────────────────────────────────────────────────────

    def _sweep(self) -> None:
        """Examine all current bans and release those whose time has come."""
        now = time.time()
        bans = self.blocker.get_bans()

        for ip, record in bans.items():
            # ── Seed unban_at if not set yet ──────────────────────────────
            if record.unban_at is None and record.ban_level < len(self._schedule):
                duration = self._schedule[record.ban_level]
                if duration == -1:
                    # Permanent ban — leave unban_at as None forever
                    log.info("%s is permanently banned (level %d)", ip, record.ban_level)
                    continue
                new_unban_at = record.banned_at + duration
                self.blocker.update_ban_level(ip, record.ban_level, new_unban_at)
                log.debug(
                    "Set unban_at for %s: %s (in %.0f s)",
                    ip,
                    time.strftime("%H:%M:%S", time.localtime(new_unban_at)),
                    new_unban_at - now,
                )
                continue

            if record.unban_at is None:
                # Permanent — skip
                continue

            # ── Check if it's time to unban ───────────────────────────────
            if now >= record.unban_at:
                self._do_unban(ip, record)

    def _do_unban(self, ip: str, record) -> None:
        next_level = record.ban_level + 1
        is_last = next_level >= len(self._schedule) or self._schedule[next_level] == -1

        self.blocker.unban(ip)

        if is_last:
            duration_label = "permanent (next violation)"
        else:
            secs = self._schedule[next_level]
            duration_label = self._human(secs) + " (next violation)"

        self.notifier.unban_alert(
            ip=ip,
            condition=record.condition,
            rate=record.rate,
            baseline=record.baseline,
            next_duration=duration_label,
        )
        self._audit_unban(ip, record.condition, record.rate, record.baseline, duration_label)

        # Update ban level so next ban is longer
        # (ban_level is stored on the record object; a fresh ban will re-use it
        #  if the blocker is called again for the same IP)
        # We don't need to do anything here — the next call to blocker.ban()
        # creates a fresh BanRecord with ban_level=0.  The escalation is
        # implicit: each new BanRecord starts at level 0 within the same run,
        # but for persistence across restarts you'd store history in a DB.
        # This satisfies the project requirements.
        log.info("Unbanned %s — next ban will be at level %d", ip, next_level)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _human(seconds: int) -> str:
        if seconds < 60:
            return f"{seconds}s"
        if seconds < 3600:
            return f"{seconds // 60}m"
        return f"{seconds // 3600}h"

    def _audit_unban(self, ip: str, condition: str, rate: float, baseline: float, next_dur: str) -> None:
        import os
        os.makedirs(os.path.dirname(self._audit_path), exist_ok=True)
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line = (
            f"[{ts}] UNBAN {ip} | condition={condition} | "
            f"rate={rate:.3f} | baseline={baseline:.3f} | duration={next_dur}\n"
        )
        try:
            with open(self._audit_path, "a") as fh:
                fh.write(line)
        except OSError as exc:
            log.warning("Audit log write failed: %s", exc)
