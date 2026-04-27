"""
detector.py — Anomaly detection engine.

Sliding-window design (deque-based, no rate-limiting libraries)
───────────────────────────────────────────────────────────────
We maintain two deques:

  1. _global_window  — timestamps of ALL requests in the last 60 s
  2. _ip_windows     — one deque per source IP, same 60-second window

Each deque stores raw Unix timestamps (float).  On every new request:
  a. Append the current timestamp.
  b. Evict all timestamps older than (now - window_duration) from the left.
     Python deques support O(1) popleft(), so eviction is cheap.
  c. len(deque) == number of requests in the last 60 seconds == req/s × 60
     Divide by window_duration to get req/s.

Why deques?
  A ring-buffer approach (maxlen) would work for fixed-rate traffic but
  fails when requests arrive in bursts — you'd evict recent events.
  Time-stamped deques with manual eviction are semantically correct
  regardless of arrival pattern.

Detection logic
───────────────
For each new request we compute:

  current_rate = len(window) / window_duration   (req/s)
  z_score      = (current_rate - baseline_mean) / baseline_stddev

We flag an anomaly if EITHER:
  • z_score      > z_score_threshold  (default 3.0)
  • current_rate > baseline_mean * rate_multiplier  (default 5×)

Error-surge tightening
──────────────────────
If an IP's 4xx+5xx rate is ≥ 3× baseline_error_mean, we multiply the
z-score threshold and rate multiplier by their respective surge factors
(both < 1), making detection more sensitive for that IP.
"""

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Dict

log = logging.getLogger("detector")


class AnomalyDetector:
    """
    Processes every parsed LogEntry and fires the blocker when thresholds
    are exceeded.
    """

    def __init__(self, cfg: dict, baseline_engine, blocker, notifier) -> None:
        self._lock = threading.Lock()

        w = cfg["sliding_window"]["duration_seconds"]
        self._window_dur: int = w  # 60 seconds

        d = cfg["detection"]
        self._z_thresh: float = d["z_score_threshold"]
        self._rate_mult: float = d["rate_multiplier"]
        self._err_mult: float = d["error_rate_multiplier"]
        self._err_z_factor: float = d["error_surge_z_factor"]
        self._err_rate_factor: float = d["error_surge_rate_factor"]

        self.baseline = baseline_engine
        self.blocker = blocker
        self.notifier = notifier

        # ── Deque-based sliding windows ────────────────────────────────────
        # Each value is a float Unix timestamp.
        # We use defaultdict so new IPs get an empty deque automatically.
        self._global_window: deque = deque()
        self._ip_windows: Dict[str, deque] = defaultdict(deque)
        self._ip_error_windows: Dict[str, deque] = defaultdict(deque)

        # Cooldown: don't re-trigger a block for the same IP within 30 s
        self._last_blocked: Dict[str, float] = {}
        self._global_alerted_at: float = 0.0

        # Stats exposed to dashboard
        self.global_rps: float = 0.0
        self.ip_rps: Dict[str, float] = {}

    # ── Main entry point ──────────────────────────────────────────────────────

    def process(self, entry) -> None:
        """
        Called by LogMonitor for every parsed log line.
        Thread-safe; must return quickly.
        """
        now = time.time()
        ip = entry.source_ip
        is_error = 400 <= entry.status < 600

        with self._lock:
            # ── 1. Update global sliding window ───────────────────────────
            self._global_window.append(now)
            self._evict(self._global_window, now)

            # ── 2. Update per-IP sliding window ───────────────────────────
            self._ip_windows[ip].append(now)
            self._evict(self._ip_windows[ip], now)

            # ── 3. Update per-IP error window ────────────────────────────
            if is_error:
                self._ip_error_windows[ip].append(now)
            self._evict(self._ip_error_windows[ip], now)

            # ── 4. Compute current rates ──────────────────────────────────
            global_rps = len(self._global_window) / self._window_dur
            ip_rps = len(self._ip_windows[ip]) / self._window_dur
            ip_err_rps = len(self._ip_error_windows[ip]) / self._window_dur

            self.global_rps = global_rps
            self.ip_rps[ip] = ip_rps

            # ── 5. Fetch current baseline ─────────────────────────────────
            mean = self.baseline.effective_mean
            stddev = self.baseline.effective_stddev
            err_mean = self.baseline.error_mean

            # ── 6. Check for error-surge tightening ───────────────────────
            tightened = ip_err_rps >= self._err_mult * err_mean and err_mean > 0
            z_thresh = self._z_thresh * (self._err_z_factor if tightened else 1.0)
            rate_mult = self._rate_mult * (self._err_rate_factor if tightened else 1.0)

            # ── 7. Per-IP anomaly check ───────────────────────────────────
            ip_z = (ip_rps - mean) / stddev if stddev > 0 else 0.0
            ip_anomalous = ip_z > z_thresh or ip_rps > mean * rate_mult

            if ip_anomalous and not self.blocker.is_banned(ip):
                cooldown_ok = (now - self._last_blocked.get(ip, 0)) > 30
                if cooldown_ok:
                    self._last_blocked[ip] = now
                    condition = (
                        f"z_score={ip_z:.2f}>{z_thresh}"
                        if ip_z > z_thresh
                        else f"rate={ip_rps:.2f}>{mean * rate_mult:.2f} (5×mean)"
                    )
                    if tightened:
                        condition += " [error-surge-tightened]"
                    log.warning(
                        "IP anomaly: %s  rps=%.2f  z=%.2f  tightened=%s",
                        ip, ip_rps, ip_z, tightened,
                    )
                    # Fire blocker in a separate thread so we don't stall parsing
                    threading.Thread(
                        target=self.blocker.ban,
                        args=(ip, condition, ip_rps, mean),
                        daemon=True,
                    ).start()

            # ── 8. Global anomaly check ───────────────────────────────────
            global_z = (global_rps - mean) / stddev if stddev > 0 else 0.0
            global_anomalous = global_z > z_thresh or global_rps > mean * rate_mult

            if global_anomalous and (now - self._global_alerted_at) > 60:
                self._global_alerted_at = now
                condition = (
                    f"global_z={global_z:.2f}>{z_thresh}"
                    if global_z > z_thresh
                    else f"global_rate={global_rps:.2f}>{mean * rate_mult:.2f}"
                )
                log.warning(
                    "GLOBAL anomaly: rps=%.2f  z=%.2f", global_rps, global_z
                )
                threading.Thread(
                    target=self.notifier.global_alert,
                    args=(condition, global_rps, mean),
                    daemon=True,
                ).start()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _evict(self, window: deque, now: float) -> None:
        """
        Remove timestamps older than (now - window_duration) from the left
        of the deque.  Because timestamps are monotonically increasing, we
        can stop as soon as we find one that's still in range.
        """
        cutoff = now - self._window_dur
        while window and window[0] < cutoff:
            window.popleft()

    def top_ips(self, n: int = 10) -> list:
        """Return the top-n IPs by current request rate (for dashboard)."""
        with self._lock:
            return sorted(self.ip_rps.items(), key=lambda x: x[1], reverse=True)[:n]

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "global_rps": round(self.global_rps, 3),
                "top_ips": self.top_ips(10),
            }
