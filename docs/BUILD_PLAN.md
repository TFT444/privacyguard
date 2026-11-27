# PrivacyGuard Build Plan

Order of work, chosen so every step is testable without the physical adapter.

## Phase 1: Detection engine (no hardware needed) -- DONE
- [x] `monitor/detection.py`: rule functions for ARP spoof, evil-twin, deauth, IoT anomaly
- [x] `monitor/frames.py`: parsed-frame data objects (decoupled from Scapy)
- [x] `tests/test_detection.py`: 13 tests, all via strict TDD (red-green)
- [x] Coverage: 100% on detection + frames (target was >= 70%)

## Phase 2: Persistence + API
- [ ] `web/db.py`: SQLite schema (devices, alerts, connections) in WAL mode
- [ ] `web/app.py`: Flask REST API (POST /api/event, GET /api/devices, /api/alerts, /api/score)
- [ ] Bearer-token auth on POST /api/event
- [ ] Safety Score computation (0-100, 24h rolling window)

## Phase 3: Dashboard
- [ ] `web/templates/`: device inventory, alert log, Safety Score, ntfy QR code
- [ ] Server-Sent Events for live updates
- [ ] IEEE OUI lookup (local file) for manufacturer names

## Phase 4: Notifications + display
- [ ] ntfy push on CRITICAL / HIGH events
- [ ] `display/oled.py`: render Safety Score on the 1.3" OLED (logic testable with a mock)

## Phase 5: Capture + deploy (needs hardware)
- [ ] `monitor/capture.py`: Scapy monitor-mode capture wired into the detection engine
- [ ] `systemd/`: two services with Restart=always, enabled at boot (24/7)
- [ ] End-to-end test: arpspoof, mdk4, hostapd on own network

## Feature ideas (parking lot)
- "New device joined your network" instant alert (cheap, demos well)
- CSV export of the alert log
- Self-hosted ntfy fallback
