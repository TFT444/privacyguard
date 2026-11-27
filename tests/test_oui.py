"""OUI (MAC-to-manufacturer) lookup tests (Phase 3). No hardware."""

from privacyguard.web.oui import normalize_oui, lookup_manufacturer

TABLE = {
    "DCA632": "Raspberry Pi Trading Ltd",
    "FCFBFB": "Samsung Electronics",
}


def test_normalize_strips_separators_and_uppercases():
    assert normalize_oui("dc:a6:32:11:22:33") == "DCA632"
    assert normalize_oui("DC-A6-32-11-22-33") == "DCA632"


def test_known_prefix_returns_manufacturer():
    assert lookup_manufacturer("dc:a6:32:aa:bb:cc", TABLE) == "Raspberry Pi Trading Ltd"


def test_unknown_prefix_returns_unknown():
    assert lookup_manufacturer("00:11:22:33:44:55", TABLE) == "Unknown"
