# PrivacyGuard Build Plan

Order of work, chosen so every step is testable without the physical adapter.

## Phase 1: Detection engine (no hardware needed) -- DONE
- [x] `monitor/detection.py`: rule functions for ARP spoof, evil-twin, deauth, IoT anomaly
- [x] `monitor/frames.py`: parsed-frame data objects (decoupled from Scapy)
- [x] `tests/test_detection.py`: 13 tests, all via strict TDD (red-green)
- [x] Coverage: 100% on detection + frames (target was >= 70%)

## Phase 2: Persistence + API -- DONE
- [x] `web/db.py`: SQLite schema (devices, alerts, connections) in WAL mode
- [x] `web/app.py`: Flask REST API (POST /api/event, GET /api/devices, /api/alerts, /api/score, ack)
- [x] Bearer-token auth on POST /api/event
- [x] `web/safety.py`: Safety Score (0-100, 24h rolling window, acknowledged ignored)

## Phase 3: Dashboard -- DONE
- [x] `web/templates/dashboard.html`: device inventory, alert log, Safety Score
- [x] Server-Sent Events endpoint for live updates (/api/stream)
- [x] `web/oui.py`: IEEE OUI lookup for manufacturer names

## Phase 4: Notifications + display -- DONE
- [x] `web/notify.py`: ntfy push on CRITICAL / HIGH events (injectable sender)
- [x] `display/oled.py`: Safety Score render logic (pure, tested); hardware push guarded

## Phase 5: Capture + deploy (needs hardware) -- REMAINING
- [ ] `monitor/capture.py`: Scapy monitor-mode capture wired into the detection engine
- [ ] `systemd/`: two services with Restart=always, enabled at boot (24/7)
- [ ] End-to-end test: arpspoof, mdk4, hostapd on own network

## Test status
38 tests passing, 92% coverage (100% on detection, safety, oui; SSE loop + hardware paths excluded).

## Feature ideas (parking lot)
- "New device joined your network" instant alert (cheap, demos well)
- CSV export of the alert log
- Self-hosted ntfy fallback
