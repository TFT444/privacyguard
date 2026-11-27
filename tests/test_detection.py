"""
Detection engine tests (Phase 1). These run with no hardware: each rule is fed
lightweight parsed-frame objects and asserted to raise (or not raise) the right
threat event.
"""

from privacyguard.monitor.detection import (
    make_event,
    detect_arp_spoof,
    detect_evil_twin,
    detect_deauth,
    detect_iot_anomaly,
)
from privacyguard.monitor.frames import (
    ArpReply,
    Beacon,
    DeauthFrame,
    OutboundConnection,
)


def test_make_event_builds_valid_event():
    ev = make_event("ARP_SPOOF", "HIGH", "aa:bb:cc:11:22:33", "test")
    assert ev["alert_type"] == "ARP_SPOOF"
    assert ev["severity"] == "HIGH"
    assert ev["device_mac"] == "aa:bb:cc:11:22:33"


# --- ARP spoofing -------------------------------------------------------------

def test_arp_reply_for_new_ip_records_mapping_and_raises_no_alert():
    table = {}
    reply = ArpReply(src_ip="192.168.1.1", src_mac="aa:bb:cc:00:00:01")
    event = detect_arp_spoof(reply, table)
    assert event is None
    assert table["192.168.1.1"] == "aa:bb:cc:00:00:01"


def test_arp_reply_with_conflicting_mac_raises_high_alert():
    table = {"192.168.1.1": "aa:bb:cc:00:00:01"}  # the real router
    attacker = ArpReply(src_ip="192.168.1.1", src_mac="de:ad:be:ef:00:99")
    event = detect_arp_spoof(attacker, table)
    assert event is not None
    assert event["alert_type"] == "ARP_SPOOF"
    assert event["severity"] == "HIGH"
    assert event["device_mac"] == "de:ad:be:ef:00:99"


def test_arp_reply_matching_known_mapping_raises_no_alert():
    table = {"192.168.1.1": "aa:bb:cc:00:00:01"}
    legit = ArpReply(src_ip="192.168.1.1", src_mac="aa:bb:cc:00:00:01")
    assert detect_arp_spoof(legit, table) is None


# --- Evil-twin access point ---------------------------------------------------

HOME_SSID = "HomeNet"
KNOWN_BSSIDS = {"aa:bb:cc:dd:ee:01"}  # the real router


def test_beacon_with_home_ssid_from_unknown_bssid_raises_critical():
    rogue = Beacon(ssid="HomeNet", bssid="66:66:66:66:66:66")
    event = detect_evil_twin(rogue, KNOWN_BSSIDS, HOME_SSID)
    assert event is not None
    assert event["alert_type"] == "EVIL_TWIN"
    assert event["severity"] == "CRITICAL"
    assert event["device_mac"] == "66:66:66:66:66:66"


def test_beacon_with_home_ssid_from_known_bssid_raises_no_alert():
    legit = Beacon(ssid="HomeNet", bssid="aa:bb:cc:dd:ee:01")
    assert detect_evil_twin(legit, KNOWN_BSSIDS, HOME_SSID) is None


def test_beacon_with_other_ssid_raises_no_alert():
    neighbour = Beacon(ssid="NeighbourWifi", bssid="12:34:56:78:9a:bc")
    assert detect_evil_twin(neighbour, KNOWN_BSSIDS, HOME_SSID) is None


# --- Deauthentication flood ---------------------------------------------------

ATTACKER = "de:ad:be:ef:00:01"
VICTIM = "11:22:33:44:55:66"


def test_deauth_below_threshold_raises_no_alert():
    tracker = {}
    frame = DeauthFrame(src_mac=ATTACKER, target_mac=VICTIM)
    # 4 frames at the same instant, threshold is 5
    results = [detect_deauth(frame, tracker, now=0.0, threshold=5, window=10.0)
               for _ in range(4)]
    assert all(r is None for r in results)


def test_deauth_reaching_threshold_within_window_raises_medium():
    tracker = {}
    frame = DeauthFrame(src_mac=ATTACKER, target_mac=VICTIM)
    events = [detect_deauth(frame, tracker, now=1.0, threshold=5, window=10.0)
              for _ in range(5)]
    assert events[:4] == [None, None, None, None]
    fired = events[4]
    assert fired is not None
    assert fired["alert_type"] == "DEAUTH_FLOOD"
    assert fired["severity"] == "MEDIUM"
    assert fired["device_mac"] == ATTACKER
    assert "5" in fired["description"]       # frame count reported
    assert VICTIM in fired["description"]    # target reported


def test_deauth_frames_outside_window_are_pruned_and_do_not_accumulate():
    tracker = {}
    frame = DeauthFrame(src_mac=ATTACKER, target_mac=VICTIM)
    # 4 old frames at t=0
    for _ in range(4):
        detect_deauth(frame, tracker, now=0.0, threshold=5, window=10.0)
    # a single frame long after the window: old ones should be pruned, count = 1
    assert detect_deauth(frame, tracker, now=100.0, threshold=5, window=10.0) is None


# --- IoT outbound anomaly -----------------------------------------------------

CAMERA = "aa:bb:cc:ca:me:ra"


def test_new_device_first_destination_seeds_baseline_without_alert():
    baselines = {}
    conn = OutboundConnection(device_mac=CAMERA, dst_ip="52.1.2.3")
    event = detect_iot_anomaly(conn, baselines)
    assert event is None
    assert "52.1.2.3" in baselines[CAMERA]


def test_known_device_known_destination_raises_no_alert():
    baselines = {CAMERA: {"52.1.2.3"}}
    conn = OutboundConnection(device_mac=CAMERA, dst_ip="52.1.2.3")
    assert detect_iot_anomaly(conn, baselines) is None


def test_known_device_new_destination_raises_low_alert():
    baselines = {CAMERA: {"52.1.2.3"}}
    conn = OutboundConnection(device_mac=CAMERA, dst_ip="203.0.113.42")
    event = detect_iot_anomaly(conn, baselines)
    assert event is not None
    assert event["alert_type"] == "IOT_ANOMALY"
    assert event["severity"] == "LOW"
    assert event["device_mac"] == CAMERA
    assert "203.0.113.42" in event["description"]
    assert "203.0.113.42" in baselines[CAMERA]  # baseline learns the new dst
