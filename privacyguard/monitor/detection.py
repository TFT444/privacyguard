"""
Detection engine: rule functions that turn captured frames into threat events.

Each rule is a pure function that takes parsed frame data (and any state it needs)
and returns a threat event dict or None. Keeping them pure makes them fully unit
testable against crafted frames, with no adapter required.

TODO (Phase 1): implement
  - detect_arp_spoof(packet, ip_mac_table)
  - detect_evil_twin(packet, known_bssids, home_ssid)
  - detect_deauth(packet, deauth_window)
  - detect_iot_anomaly(packet, device_baselines)
"""

SEVERITY = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def make_event(alert_type, severity, device_mac, description):
    """Build the standard threat-event dict sent to the API."""
    assert severity in SEVERITY
    return {
        "alert_type": alert_type,
        "severity": severity,
        "device_mac": device_mac,
        "description": description,
    }


def detect_arp_spoof(reply, ip_mac_table):
    """
    Detect ARP spoofing by comparing each ARP reply against a known IP-to-MAC map.

    If the sender IP is already mapped to a different MAC, an attacker is claiming
    a legitimate IP, so raise a HIGH alert. Otherwise record the mapping and return
    None. `ip_mac_table` is mutated in place to hold the running baseline.
    """
    known_mac = ip_mac_table.get(reply.src_ip)
    if known_mac is not None and known_mac != reply.src_mac:
        return make_event(
            "ARP_SPOOF",
            "HIGH",
            reply.src_mac,
            f"ARP reply for {reply.src_ip} claims MAC {reply.src_mac}, "
            f"but it is known at {known_mac}.",
        )
    ip_mac_table[reply.src_ip] = reply.src_mac
    return None


def detect_evil_twin(beacon, known_bssids, home_ssid):
    """
    Detect an evil-twin access point: a beacon advertising the home SSID from a
    BSSID (AP hardware address) that is not on the known-good list. Raises a
    CRITICAL alert, since a matching-name rogue AP is a direct interception threat.
    """
    if beacon.ssid == home_ssid and beacon.bssid not in known_bssids:
        return make_event(
            "EVIL_TWIN",
            "CRITICAL",
            beacon.bssid,
            f"Access point {beacon.bssid} is broadcasting your network name "
            f"'{home_ssid}' but is not your known router.",
        )
    return None


def detect_deauth(frame, tracker, now, threshold=5, window=10.0):
    """
    Detect a deauthentication flood using a per-source sliding time window.

    `tracker` maps a source MAC to the timestamps of its recent deauth frames.
    Frames older than `window` seconds are pruned. When a source reaches
    `threshold` frames inside the window, raise a MEDIUM alert and reset that
    source's window so the alert does not fire again on every subsequent frame.
    The clock (`now`) is passed in so the behaviour is deterministic and testable.
    """
    times = tracker.setdefault(frame.src_mac, [])
    times.append(now)
    # prune anything outside the sliding window
    times[:] = [t for t in times if now - t < window]

    if len(times) >= threshold:
        count = len(times)
        tracker[frame.src_mac] = []  # reset to avoid repeat alerts
        return make_event(
            "DEAUTH_FLOOD",
            "MEDIUM",
            frame.src_mac,
            f"{count} deauthentication frames from {frame.src_mac} targeting "
            f"{frame.target_mac} within {window:.0f}s.",
        )
    return None


def detect_iot_anomaly(conn, baselines):
    """
    Detect an IoT device contacting a destination outside its learned baseline.

    `baselines` maps a device MAC to the set of destination IPs it has been seen
    contacting. A device seen for the first time seeds its baseline silently
    (learning), so the dashboard is not flooded on first run. Once a device has a
    baseline, a brand-new destination raises a LOW alert and is then learned.
    """
    known = baselines.get(conn.device_mac)
    if known is None:
        baselines[conn.device_mac] = {conn.dst_ip}  # learning: seed, no alert
        return None
    if conn.dst_ip in known:
        return None
    known.add(conn.dst_ip)
    return make_event(
        "IOT_ANOMALY",
        "LOW",
        conn.device_mac,
        f"Device {conn.device_mac} contacted a new destination {conn.dst_ip} "
        f"not seen in its recent baseline.",
    )
