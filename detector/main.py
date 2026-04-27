#!/usr/bin/env python3
"""
main.py — HNG Anomaly Detector entry point.

Boots every component in the right order, wires them together,
and keeps the process alive until a SIGTERM/SIGINT arrives.
"""

import logging
import signal
import sys
import threading
import time

import yaml

from monitor import LogMonitor
from baseline import BaselineEngine
from detector import AnomalyDetector
from blocker import Blocker
from unbanner import Unbanner
from notifier import SlackNotifier
from dashboard import DashboardServer

# ── Global logger ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("main")


def load_config(path: str = "/app/config.yaml") -> dict:
    """Load YAML config; fall back to local path for development."""
    for candidate in (path, "config.yaml", "detector/config.yaml"):
        try:
            with open(candidate) as fh:
                cfg = yaml.safe_load(fh)
                log.info("Loaded config from %s", candidate)
                return cfg
        except FileNotFoundError:
            continue
    raise RuntimeError("config.yaml not found in any expected location")


def main() -> None:
    cfg = load_config()

    # ── Wire up shared state objects ─────────────────────────────────────────
    notifier = SlackNotifier(cfg)
    blocker = Blocker(cfg, notifier)
    unbanner = Unbanner(cfg, blocker, notifier)
    baseline_engine = BaselineEngine(cfg)
    detector = AnomalyDetector(cfg, baseline_engine, blocker, notifier)
    monitor = LogMonitor(cfg, detector, baseline_engine)

    # ── Launch the HTTP dashboard in a daemon thread ──────────────────────────
    dashboard = DashboardServer(cfg, baseline_engine, blocker, unbanner, monitor)
    dash_thread = threading.Thread(target=dashboard.serve_forever, daemon=True)
    dash_thread.start()
    log.info(
        "Dashboard live at http://0.0.0.0:%d", cfg["dashboard"]["port"]
    )

    # ── Start the periodic unbanner ───────────────────────────────────────────
    unban_thread = threading.Thread(target=unbanner.run, daemon=True)
    unban_thread.start()

    # ── Start the baseline recalculator ──────────────────────────────────────
    baseline_thread = threading.Thread(target=baseline_engine.run, daemon=True)
    baseline_thread.start()

    # ── Graceful shutdown on SIGTERM / SIGINT ─────────────────────────────────
    shutdown_event = threading.Event()

    def _shutdown(signum, frame):  # noqa: ANN001
        log.info("Signal %s received — shutting down", signum)
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    # ── Start tailing the log (blocking call inside its own thread) ───────────
    monitor_thread = threading.Thread(target=monitor.tail, daemon=True)
    monitor_thread.start()

    log.info("HNG Anomaly Detector is running. Tailing %s", cfg["log"]["path"])

    # Block until shutdown signal
    shutdown_event.wait()
    log.info("Goodbye.")
    sys.exit(0)


if __name__ == "__main__":
    main()
