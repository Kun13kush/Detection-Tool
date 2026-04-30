# HNG Anomaly Detector — cloud.ng Traffic Guardian

> A real-time HTTP traffic anomaly detection engine built for HNG's cloud.ng Nextcloud platform. Continuously monitors Nginx access logs, learns what normal traffic looks like, and automatically blocks suspicious IPs using iptables — all without any rate-limiting libraries.

---

## 📋 Table of Contents

1. [Live Server Info](#live-server-info)
2. [Architecture Overview](#architecture-overview)
3. [Language Choice](#language-choice)
4. [How the Sliding Window Works](#how-the-sliding-window-works)
5. [How the Baseline Works](#how-the-baseline-works)
6. [Detection Logic](#detection-logic)
7. [iptables Blocking](#iptables-blocking)
8. [Auto-Unban Backoff](#auto-unban-backoff)
9. [Slack Alerts](#slack-alerts)
10. [Repository Structure](#repository-structure)
11. [Setup Instructions (Fresh VPS)](#setup-instructions-fresh-vps)
12. [Configuration Reference](#configuration-reference)
13. [Blog Post](#blog-post)

---

## Live Server Info

| Item | Value |
|------|-------|
| **Server IP** | `<YOUR_VPS_IP>` |
| **Nextcloud** | `http://<YOUR_VPS_IP>` (IP only) |
| **Metrics Dashboard** | `http://<YOUR_DASHBOARD_DOMAIN>:8080` |
| **GitHub Repo** | `https://github.com/<YOUR_USERNAME>/hng-anomaly-detector` |

---

## Architecture Overview

```
Internet
    │
    ▼
┌──────────┐   JSON logs   ┌─────────────────────┐
│  Nginx   │──────────────▶│  HNG-nginx-logs      │
│ :80      │               │  (Docker volume)     │
└──────────┘               └──────────┬──────────┘
    │                                  │  tail (read-only)
    │ proxy_pass                       ▼
    ▼                      ┌─────────────────────┐
┌──────────┐               │  detector/          │
│Nextcloud │               │  ├── monitor.py     │  parse lines
│ :80      │               │  ├── baseline.py    │  rolling 30-min stats
└──────────┘               │  ├── detector.py    │  z-score + 5× check
                           │  ├── blocker.py     │  iptables DROP
                           │  ├── unbanner.py    │  backoff unban
                           │  ├── notifier.py    │  Slack webhooks
                           │  └── dashboard.py   │  HTTP :8080
                           └─────────────────────┘
```

All three services share the `HNG-nginx-logs` Docker named volume. Nginx writes to it; the detector and Nextcloud mount it read-only.

---

## Language Choice

**Python 3.11** — chosen for:

- **Rapid iteration**: The standard library provides `collections.deque`, `threading`, `http.server`, and `subprocess` — everything we need without third-party frameworks.
- **Readability**: The detection math (z-score, mean, stddev) reads exactly like the textbook formula.
- **Deployment simplicity**: One `pip install -r requirements.txt` and the daemon starts. No compilation step.
- **Ecosystem**: `psutil` gives CPU/memory stats; `pyyaml` handles config.

The only external dependencies are `pyyaml` and `psutil`. No rate-limiting libraries, no Fail2Ban, no framework magic.

---

## How the Sliding Window Works

### The Problem with Simple Counters

A naïve approach would count requests in the current minute (`counter += 1`, reset every 60 s). The problem: a burst at 00:59 and 01:01 registers as "2 requests" even though 2 requests in 2 seconds is very different from 2 requests in 2 minutes.

### Deque-Based Sliding Windows

We use `collections.deque` — a double-ended queue — to store **raw timestamps** of every request.

```python
from collections import deque

# One global window, one per IP
global_window: deque = deque()           # stores float timestamps
ip_windows: dict[str, deque] = defaultdict(deque)
WINDOW_DURATION = 60  # seconds
```

**On every incoming request:**

```python
def process(entry):
    now = time.time()
    ip = entry.source_ip

    # 1. Append new timestamp to both windows
    global_window.append(now)
    ip_windows[ip].append(now)

    # 2. Evict timestamps older than 60 seconds from the LEFT
    #    (timestamps are monotonically increasing, so we stop
    #     as soon as we hit one that's still in range)
    cutoff = now - WINDOW_DURATION
    while global_window and global_window[0] < cutoff:
        global_window.popleft()   # O(1) — deque is a doubly-linked list
    while ip_windows[ip] and ip_windows[ip][0] < cutoff:
        ip_windows[ip].popleft()

    # 3. Current rate = count of events in last 60 s
    global_rps = len(global_window) / WINDOW_DURATION
    ip_rps     = len(ip_windows[ip]) / WINDOW_DURATION
```

**Why this is correct:**
- `len(deque)` always equals exactly the number of requests in the last 60 seconds, regardless of when they arrived.
- Eviction is O(1) per call because timestamps are always appended to the right in sorted order — we only ever need to popleft until we hit a fresh one.
- No timer, no reset, no fixed bucket: the window smoothly slides forward with real time.

**Memory bound:**
At 10,000 req/s (an extreme DDoS), the global window holds at most 600,000 float timestamps ≈ 4.8 MB. Per-IP windows are much smaller. This is acceptable.

---

## How the Baseline Works

The baseline answers: *"What is normal traffic on this server right now?"*

### Data Collection

Every parsed log line calls `baseline_engine.record(entry)`:

```python
def record(self, entry):
    now_sec = int(time.time())
    bucket[now_sec] += 1          # count requests per second
    if 400 <= entry.status < 600:
        error_bucket[now_sec] += 1
```

We bucket requests into integer-second slots. Multiple requests in the same second all increment the same counter.

### 30-Minute Rolling Window

Every 60 seconds, `_recalculate()` runs in a background thread:

```python
# Flush current-second buckets into the sliding deque (maxlen=1800)
for sec, count in sorted(bucket.items()):
    window.append((sec, count))   # deque auto-evicts oldest when full
bucket.clear()

# Compute mean and stddev over the last 30 minutes
counts = [c for _, c in window]
mean   = sum(counts) / len(counts)
var    = sum((x - mean)**2 for x in counts) / len(counts)
stddev = math.sqrt(var)
```

The deque has `maxlen=1800` (30 × 60 seconds). When a new element is appended and the deque is full, Python automatically drops the oldest from the left — zero manual eviction code needed here.

### Per-Hour Slot Preference

Traffic patterns differ by hour. Midnight traffic is much lower than midday. If we always averaged across the last 30 minutes at 12:01, we'd include 30 minutes of data that might straddle a low-to-high transition.

We maintain a `hour_slots` dict: `{hour: [per-second counts...]}`. When the current hour has ≥ 10 samples, we prefer the current-hour mean/stddev over the global 30-minute window:

```python
hour_counts = hour_slots[current_hour]
if len(hour_counts) >= MIN_SAMPLES:
    hour_mean   = sum(hour_counts) / len(hour_counts)
    hour_stddev = sqrt(variance(hour_counts))
    if hour_mean > floor_mean:
        mean, stddev = hour_mean, hour_stddev
```

### Floor Values

To prevent division-by-zero and over-sensitivity at near-zero traffic:

```python
effective_mean   = max(mean,   floor_mean)    # default: 0.5 req/s
effective_stddev = max(stddev, floor_stddev)  # default: 0.1
```

This means a single request from a totally quiet server won't instantly trigger a z-score of 10.

### Audit Log Entry

Every recalculation writes a structured line:

```
[2025-04-25T14:00:00Z] BASELINE_RECALC ip=global | condition=periodic | rate=2.341 | baseline=2.341 | stddev=0.812
```

---

## Detection Logic

### Z-Score Method

The z-score measures how many standard deviations a value is from the mean:

```
z = (current_rate - baseline_mean) / baseline_stddev
```

If `z > 3.0`, the current rate is 3 standard deviations above normal — a statistically extreme event (p < 0.003 under a normal distribution).

### 5× Multiplier

For situations where stddev is small but the rate is clearly excessive:

```
flag if current_rate > baseline_mean × 5
```

Whichever fires first triggers the response.

### Error Surge Tightening

If an IP's 4xx/5xx rate is ≥ 3× the baseline error rate, we tighten the thresholds:

```python
if ip_err_rps >= 3 * error_mean:
    z_threshold  *= 0.6   # more sensitive (was 3.0, now 1.8)
    rate_mult    *= 0.5   # more sensitive (was 5×, now 2.5×)
```

This catches credential-stuffing attacks (many 401s) and path-scanning (many 404s) earlier.

### Full Decision Flow

```
For each request from IP X:
  1. Append timestamp to global_window and ip_windows[X]
  2. Evict old timestamps (> 60 s ago)
  3. ip_rps     = len(ip_windows[X]) / 60
  4. global_rps = len(global_window) / 60
  5. ip_z       = (ip_rps - mean) / stddev
  6. Is ip's error rate 3× baseline? → tighten thresholds
  7. IF ip_z > threshold OR ip_rps > mean×mult:
       → blocker.ban(X)    [IP-level: iptables + Slack]
  8. IF global_z > threshold OR global_rps > mean×mult:
       → notifier.global_alert()   [no block]
```

---

## iptables Blocking

When an IP is flagged, `blocker.ban(ip)` runs:

```python
subprocess.run([
    "iptables", "-I", "INPUT", "1",
    "-s", ip,
    "-j", "DROP"
])
```

`-I INPUT 1` inserts the rule at the **top** of the INPUT chain so it's evaluated first, before any ACCEPT rules. Subsequent packets from that IP are silently dropped — no TCP RST, no HTTP response.

To verify bans:

```bash
sudo iptables -L INPUT -n --line-numbers
```

To remove (done automatically by unbanner):

```bash
iptables -D INPUT -s <IP> -j DROP
```

The detector container requires `cap_add: [NET_ADMIN]` in Docker Compose and runs with `network_mode: host` so its iptables rules affect the host network namespace.

---

## Auto-Unban Backoff

Bans escalate if an IP keeps misbehaving:

| Offense | Ban Duration |
|---------|-------------|
| 1st     | 10 minutes  |
| 2nd     | 30 minutes  |
| 3rd     | 2 hours     |
| 4th+    | Permanent   |

The unbanner polls every 10 seconds:

```python
def _sweep():
    for ip, record in blocker.get_bans().items():
        if record.unban_at and time.time() >= record.unban_at:
            blocker.unban(ip)
            notifier.unban_alert(ip, ...)
```

A Slack message is sent on every unban.

---

## Slack Alerts

Configure your webhook in `detector/config.yaml`:

```yaml
slack:
  webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

Three alert types:

**Ban Alert** (within 10 s of detection):
```
🚨 IP BANNED — `1.2.3.4`
> Condition: `z_score=4.21>3.0`
> Rate: `45.20 req/s`
> Baseline: `2.30 req/s`
> Ban Duration: `10 minutes`
> Time: `2025-04-25T14:23:01Z`
```

**Unban Alert:**
```
✅ IP UNBANNED — `1.2.3.4`
> Next violation duration: `30 minutes (next violation)`
```

**Global Alert:**
```
⚠️ GLOBAL TRAFFIC ANOMALY
> Condition: `global_z=5.10>3.0`
> Global Rate: `312.40 req/s`
> Baseline: `8.20 req/s`
> Action: Alert only (no block applied)
```

---

## Repository Structure

```
hng-anomaly-detector/
├── detector/
│   ├── main.py          # Entry point — wires all modules together
│   ├── monitor.py       # Tails Nginx log, parses JSON lines
│   ├── baseline.py      # Rolling 30-min baseline (mean, stddev)
│   ├── detector.py      # Sliding-window + z-score anomaly detection
│   ├── blocker.py       # iptables DROP rules + audit log
│   ├── unbanner.py      # Backoff unban schedule
│   ├── notifier.py      # Slack webhook notifications
│   ├── dashboard.py     # Live HTTP metrics dashboard (port 8080)
│   ├── config.yaml      # All thresholds in one place
│   ├── requirements.txt
│   └── Dockerfile
├── nginx/
│   └── nginx.conf       # Reverse proxy + JSON access log config
├── docs/
│   └── architecture.png
├── screenshots/
│   ├── Tool-running.png
│   ├── Ban-slack.png
│   ├── Unban-slack.png
│   ├── Global-alert-slack.png
│   ├── Iptables-banned.png
│   ├── Audit-log.png
│   └── Baseline-graph.png
├── docker-compose.yml
└── README.md
```

---

## Setup Instructions (Fresh VPS)

### Prerequisites

- Ubuntu 22.04 LTS (or 24.04)
- Minimum 2 vCPU, 2 GB RAM
- Root or sudo access
- A Slack incoming webhook URL
- (Optional) A domain/subdomain pointing to your server

### Step 1 — Install Docker and Docker Compose

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Verify
docker --version
docker compose version
```

### Step 2 — Clone the Repository

```bash
git clone https://github.com/<YOUR_USERNAME>/hng-anomaly-detector.git
cd hng-anomaly-detector
```

### Step 3 — Configure Slack Webhook

```bash
nano detector/config.yaml
```

Replace `YOUR/WEBHOOK/URL` with your actual Slack incoming webhook URL.

### Step 4 — Configure Nextcloud Trusted Domain

Edit `docker-compose.yml` and set:

```yaml
environment:
  - NEXTCLOUD_TRUSTED_DOMAINS=<YOUR_VPS_IP>
```

### Step 5 — Deploy the Stack

```bash
docker compose up -d --build
```

Wait 30–60 seconds for Nextcloud to initialize, then verify all three containers are running:

```bash
docker compose ps
```

Expected output:
```
NAME            STATUS
hng-nginx       running
hng-nextcloud   running
hng-detector    running
```

### Step 6 — Verify the Dashboard

```bash
curl http://localhost:8080/health
# → {"ok": true}
```

Open `http://<YOUR_VPS_IP>:8080` in a browser to see the live dashboard.

### Step 7 — Verify Nginx JSON Logging

```bash
# Trigger a request
curl http://localhost/

# Check the log
docker exec hng-nginx cat /var/log/nginx/hng-access.log | tail -3 | python3 -m json.tool
```

### Step 8 — (Optional) Set Up a Domain for the Dashboard

If you have a domain, point a subdomain (e.g., `metrics.yourdomain.com`) to your VPS IP, then add a second Nginx server block (or use Caddy) to reverse-proxy port 8080.

### Step 9 — Monitor the Detector Logs

```bash
# Live detector output
docker logs -f hng-detector

# Audit log
docker exec hng-detector cat /var/log/detector/audit.log
```

### Troubleshooting

| Issue | Fix |
|-------|-----|
| Nextcloud not loading | Wait 60 s for init; check `docker logs hng-nextcloud` |
| Dashboard returns 502 | Detector may be starting; wait 5 s and retry |
| iptables permission denied | Ensure `cap_add: [NET_ADMIN]` and `network_mode: host` in compose |
| Log file not found | Nginx may not have received a request yet; `curl http://localhost/` |

### Testing the Detector Locally

```bash
# Simulate a traffic spike by writing fake JSON log lines
for i in $(seq 1 200); do
  echo '{"source_ip":"10.0.0.99","timestamp":"2025-04-25T12:00:00+00:00","method":"GET","path":"/","status":200,"response_size":1024}' \
    >> /var/log/nginx/hng-access.log
done
```

Watch the detector logs and Slack for ban notifications.

---

## Configuration Reference

All detection thresholds live in `detector/config.yaml`. No values are hardcoded in Python.

| Key | Default | Description |
|-----|---------|-------------|
| `sliding_window.duration_seconds` | `60` | Width of per-IP and global request window |
| `baseline.window_minutes` | `30` | Rolling history for mean/stddev |
| `baseline.recalc_interval_seconds` | `60` | How often to recompute baseline |
| `baseline.floor_mean` | `0.5` | Minimum mean to prevent over-sensitivity |
| `baseline.floor_stddev` | `0.1` | Minimum stddev |
| `detection.z_score_threshold` | `3.0` | Flag if z > this |
| `detection.rate_multiplier` | `5.0` | Flag if rate > mean × this |
| `detection.error_rate_multiplier` | `3.0` | Error-surge trigger multiplier |
| `unban.schedule` | `[600,1800,7200,-1]` | Seconds for each ban level (-1 = permanent) |

---

## Blog Post

📖 **[How I Built a Real-Time Traffic Anomaly Detector for a Cloud Storage Platform](#)**

Published on: https://medium.com/@olakunle.kushehin/a-step-by-step-guide-to-building-a-real-time-http-anomaly-detector-using-python-deques-and-73ea6db405e9

The post covers:
- What this project does and why security monitoring matters
- How the sliding window detects bursts in real time
- How the baseline learns from actual traffic patterns
- How the z-score makes a statistically sound detection decision
- How iptables silently drops packets from malicious IPs

---

*Built for HNG Internship — DevSecOps Track*
