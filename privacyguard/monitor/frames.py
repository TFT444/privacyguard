"""
Lightweight parsed-frame data objects.

The detection rules operate on these plain objects, not raw Scapy packets, so the
whole detection engine is testable with no hardware or Scapy dependency. The capture
layer (Phase 5) is responsible for translating real Scapy packets into these objects.
"""

from dataclasses import dataclass


@dataclass
class ArpReply:
    """An ARP 'is-at' reply: the sender claims src_ip is at src_mac."""
    src_ip: str
    src_mac: str


@dataclass
class Beacon:
    """An 802.11 beacon frame advertising a network (ssid) from an AP (bssid)."""
    ssid: str
    bssid: str


@dataclass
class DeauthFrame:
    """An 802.11 deauthentication management frame from src_mac aimed at target_mac."""
    src_mac: str
    target_mac: str


@dataclass
class OutboundConnection:
    """A device (device_mac) contacting an external destination (dst_ip)."""
    device_mac: str
    dst_ip: str
