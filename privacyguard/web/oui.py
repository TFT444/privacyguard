"""
IEEE OUI lookup: map a MAC address to a manufacturer name using a locally cached
table (the first three octets, the Organisationally Unique Identifier). Kept local
so manufacturer resolution needs no internet during monitoring.
"""


def normalize_oui(mac):
    """Return the 6-hex-digit uppercase OUI prefix from any MAC format."""
    hexonly = mac.replace(":", "").replace("-", "").replace(".", "").upper()
    return hexonly[:6]


def lookup_manufacturer(mac, table):
    """Return the manufacturer for a MAC, or 'Unknown' if not in the table."""
    return table.get(normalize_oui(mac), "Unknown")
