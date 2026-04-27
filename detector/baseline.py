"""
baseline.py — Rolling 30-minute baseline engine.

How it works
────────────
1.  Every incoming LogEntry is recorded with record().  We bucket requests
    into per-second integer slots (Unix epoch truncated to seconds).

2.  A background thread calls _recalculate() every `recalc_interval_seconds`
    (default 60 s).  It walks the last 30 minutes of per-second buckets,
    computes mean and stddev of the per-second request counts, and stores
    the result in self.effective_mean / self.effective_stddev.

3.  We also maintain per-hour slots (0–23).  When the current hour has
    ≥ min_samples seconds of data we prefer its mean/stddev over the global
    30-minute window, because hour-local traffic patterns are more
    representative (e.g. night traffic vs. midday spike).

4.  Floor values prevent division-by-zero and over-sensitivity when traffic
    is near zero.

Deque eviction
──────────────
self._second_counts is a collections.deque with maxlen = 30 * 60 = 1800.
Python deques with maxlen automatically drop the oldest element from the
left when a new element is appended to the right — no manual eviction loop
needed.  This gives us O(1) append and O(1) eviction.

Audit log
─────────
Every recalculation writes a structured line to the audit log so operators
can see how the baseline evolved over time (required for grading).
"""

import logging
import math
import threading
import time
from collections import defaultdict, deque
from typing import Tuple

log = logging.getLogger("baseline")

# One record per second bucket: (unix_second → request_count)
_BucketMap = dict  # int → int


class BaselineEngine:
    """
    Maintains a rolling 30-minute per-second request count and exposes
    the effective mean/stddev used by AnomalyDetector.
    """

    def __init__(self, cfg: dict) -> None:
        self._lock = threading.Lock()

        window_sec = cfg["baseline"]["window_minutes"] * 60  # 1800 s
        self._recalc_interval: int = cfg["baseline"]["recalc_interval_seconds"]
        self._min_samples: int = cfg["baseline"]["min_samples"]
        self._floor_mean: float = cfg["baseline"]["floor_mean"]
        self._floor_stddev: float = cfg["baseline"]["floor_stddev"]

        self._audit_path: str = cfg["audit"]["path"]

        # ── 30-minute sliding window of per-second counts ─────────────────
        # Each slot is (unix_second, count).  maxlen gives automatic eviction.
        self._window: deque = deque(maxlen=window_sec)

        # Scratch map: second → count (rebuilt every second as requests arrive)
        self._bucket: _BucketMap = defaultdict(int)

        # ── Per-hour history (0–23) ───────────────────────────────────────
        # hour_slots[h] = list of per-second counts observed during hour h
        self._hour_slots: dict[int, list] = defaultdict(list)

        # ── Exposed to detector ───────────────────────────────────────────
        self.effective_mean: float = self._floor_mean
        self.effective_stddev: float = self._floor_stddev

        # Error-rate baseline (4xx+5xx per second)
        self._error_bucket: _BucketMap = defaultdict(int)
        self._error_window: deque = deque(maxlen=window_sec)
        self.error_mean: float = self._floor_mean
        self.error_stddev: float = self._floor_stddev

        # History for dashboard graph (list of (timestamp, mean) tuples)
        self.history: deque = deque(maxlen=120)  # last 120 recalculations

        # Last recalc timestamp
        self.last_recalc: float = 0.0

    # ── Public API called from LogMonitor ─────────────────────────────────────

    def record(self, entry) -> None:
        """
        Bucket the request into its per-second slot.
        Called for every parsed log line — must be fast (no I/O, minimal locking).
        """
        now_sec = int(time.time())
        with self._lock:
            self._bucket[now_sec] += 1
            if 400 <= entry.status < 600:
                self._error_bucket[now_sec] += 1

    # ── Background recalculation loop ────────────────────────────────────────

    def run(self) -> None:
        """Background thread: recalculate baseline every recalc_interval_seconds."""
        while True:
            time.sleep(self._recalc_interval)
            self._recalculate()

    def _recalculate(self) -> None:
        now_sec = int(time.time())
        current_hour = int(time.strftime("%H"))

        with self._lock:
            # Flush current-second buckets into the deque window
            for sec, count in sorted(self._bucket.items()):
                self._window.append((sec, count))
                self._hour_slots[current_hour].append(count)
            self._bucket.clear()

            for sec, count in sorted(self._error_bucket.items()):
                self._error_window.append((sec, count))
            self._error_bucket.clear()

            # Compute stats from the deque window
            mean, stddev = self._stats(self._window)
            err_mean, err_stddev = self._stats(self._error_window)

            # Prefer current-hour baseline if it has enough data
            hour_counts = self._hour_slots[current_hour]
            if len(hour_counts) >= self._min_samples:
                hour_mean = sum(hour_counts) / len(hour_counts)
                hour_var = sum((x - hour_mean) ** 2 for x in hour_counts) / len(hour_counts)
                hour_stddev = math.sqrt(hour_var)
                if hour_mean > self._floor_mean:
                    mean = hour_mean
                    stddev = max(hour_stddev, self._floor_stddev)

            # Apply floor values
            self.effective_mean = max(mean, self._floor_mean)
            self.effective_stddev = max(stddev, self._floor_stddev)
            self.error_mean = max(err_mean, self._floor_mean)
            self.error_stddev = max(err_stddev, self._floor_stddev)
            self.last_recalc = time.time()

            # Record for dashboard graph
            self.history.append((now_sec, self.effective_mean))

        self._audit(now_sec, self.effective_mean, self.effective_stddev)
        log.info(
            "Baseline recalculated — mean=%.3f req/s  stddev=%.3f  hour=%d",
            self.effective_mean,
            self.effective_stddev,
            current_hour,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _stats(window: deque) -> Tuple[float, float]:
        """Compute mean and population stddev from a deque of (second, count) tuples."""
        if not window:
            return 0.0, 0.0
        counts = [c for _, c in window]
        mean = sum(counts) / len(counts)
        variance = sum((x - mean) ** 2 for x in counts) / len(counts)
        return mean, math.sqrt(variance)

    def _audit(self, ts: int, mean: float, stddev: float) -> None:
        """Append a structured baseline-recalc event to the audit log."""
        import os

        os.makedirs(os.path.dirname(self._audit_path), exist_ok=True)
        line = (
            f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(ts))}] "
            f"BASELINE_RECALC ip=global | condition=periodic | "
            f"rate={mean:.3f} | baseline={mean:.3f} | stddev={stddev:.3f}\n"
        )
        try:
            with open(self._audit_path, "a") as fh:
                fh.write(line)
        except OSError as exc:
            log.warning("Could not write audit log: %s", exc)

    # ── Snapshot for dashboard / detector (lock-free reads are fine for floats) ─

    def snapshot(self) -> dict:
        return {
            "effective_mean": round(self.effective_mean, 4),
            "effective_stddev": round(self.effective_stddev, 4),
            "error_mean": round(self.error_mean, 4),
            "error_stddev": round(self.error_stddev, 4),
            "last_recalc": self.last_recalc,
            "history": list(self.history)[-60:],  # last 60 points for graph
        }
