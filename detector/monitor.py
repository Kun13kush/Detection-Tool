"""
monitor.py — Continuously tails the Nginx JSON access log line by line.

Design decisions
────────────────
• We open the file in text mode and call readline() in a tight loop.
  When there is no new data we sleep briefly so we don't spin-burn CPU.
• On truncation (log rotation) we seek back to the start of the new file.
• Every parsed line is handed directly to the AnomalyDetector and the
  BaselineEngine so they both see every request.
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("monitor")


@dataclass
class LogEntry:
    """One parsed HTTP request record from the Nginx JSON log."""

    source_ip: str
    timestamp: str
    method: str
    path: str
    status: int
    response_size: int
    raw: dict = field(default_factory=dict)


class LogMonitor:
    """
    Tails /var/log/nginx/hng-access.log and dispatches each parsed
    LogEntry to the detector and baseline engine.

    Sliding-window statistics are maintained inside AnomalyDetector;
    this class is purely responsible for I/O and parsing.
    """

    def __init__(self, cfg: dict, detector, baseline_engine) -> None:
        self.log_path: str = cfg["log"]["path"]
        self.detector = detector
        self.baseline_engine = baseline_engine

        # Public counters for the dashboard
        self.lines_processed: int = 0
        self.parse_errors: int = 0
        self._start_time: float = time.time()

    # ── Public API ────────────────────────────────────────────────────────────

    def tail(self) -> None:
        """
        Block forever, reading new log lines as Nginx writes them.
        Handles log rotation by detecting file shrinkage (inode size drop).
        """
        log.info("Tailing %s", self.log_path)
        fh = self._open_log()
        last_size = 0

        while True:
            line = fh.readline()

            if not line:
                # No new data — check for rotation
                try:
                    current_size = os.path.getsize(self.log_path)
                except FileNotFoundError:
                    current_size = 0

                if current_size < last_size:
                    log.info("Log rotation detected — reopening %s", self.log_path)
                    fh.close()
                    fh = self._open_log()
                    last_size = 0
                else:
                    last_size = current_size
                    time.sleep(0.05)  # 50 ms poll interval
                continue

            entry = self._parse(line.strip())
            if entry is not None:
                self.lines_processed += 1
                # Feed both the detector and the baseline engine
                self.baseline_engine.record(entry)
                self.detector.process(entry)
            else:
                self.parse_errors += 1

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self._start_time

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _open_log(self):
        """Open the log file, waiting until it exists."""
        while True:
            try:
                fh = open(self.log_path, "r", encoding="utf-8", errors="replace")
                fh.seek(0, 2)  # Seek to end so we only process new lines
                log.info("Opened %s", self.log_path)
                return fh
            except FileNotFoundError:
                log.warning("%s not found yet — retrying in 2 s", self.log_path)
                time.sleep(2)

    def _parse(self, line: str) -> Optional[LogEntry]:
        """
        Parse a single JSON log line into a LogEntry.

        Expected Nginx log format (configured in nginx.conf):
        {
          "source_ip": "1.2.3.4",
          "timestamp": "2025-04-25T12:34:56+00:00",
          "method": "GET",
          "path": "/index.php",
          "status": 200,
          "response_size": 1024
        }
        """
        if not line:
            return None
        try:
            data = json.loads(line)
            return LogEntry(
                source_ip=str(data.get("source_ip", data.get("remote_addr", "0.0.0.0"))),
                timestamp=str(data.get("timestamp", data.get("time_local", ""))),
                method=str(data.get("method", data.get("request_method", "GET"))),
                path=str(data.get("path", data.get("uri", "/"))),
                status=int(data.get("status", 0)),
                response_size=int(data.get("response_size", data.get("body_bytes_sent", 0))),
                raw=data,
            )
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            log.debug("Failed to parse line %r: %s", line[:120], exc)
            return None
