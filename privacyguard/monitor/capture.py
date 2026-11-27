"""
Passive capture (Phase 5, needs the USB adapter in monitor mode).

Wraps Scapy sniff() and feeds each frame to the detection engine. Until the
hardware is available, detection is tested directly with crafted frames and
recorded pcap fixtures, so this module stays thin.

TODO (Phase 5):
  - start_capture(interface, on_event): sniff() loop feeding detection rules
  - replay_pcap(path, on_event): drive the same engine from a recorded capture
"""
