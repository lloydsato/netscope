"""MAC address vendor (OUI) lookup.

Resolves the manufacturer of a device from the first 3 octets of its MAC
address using a bundled snapshot of the IEEE MA-L registry (~40k vendors),
so it works fully offline. Also detects locally-administered / randomized
MACs, which modern phones use for privacy -- itself a useful signal when
you're trying to identify a device.
"""

import gzip
import json
import os
import functools
import warnings

_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "oui.json.gz")


@functools.lru_cache(maxsize=1)
def _load_db():
    try:
        with gzip.open(_DATA_PATH, "rb") as f:
            return json.loads(f.read().decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        warnings.warn(
            f"netscope: could not load the bundled OUI database ({_DATA_PATH}: {e}); "
            f"vendor lookups will report 'unknown'.",
            RuntimeWarning, stacklevel=2,
        )
        return {}


def _normalize(mac: str) -> str:
    """Return the OUI prefix 'AA:BB:CC' (uppercased) from any common MAC format."""
    hexchars = [c for c in mac.upper() if c in "0123456789ABCDEF"]
    if len(hexchars) < 6:
        return ""
    first6 = "".join(hexchars[:6])
    return ":".join(first6[i:i + 2] for i in (0, 2, 4))


def is_locally_administered(mac: str) -> bool:
    """True if the MAC is locally administered (2nd-least-significant bit of the
    first octet is set). Randomized/privacy MACs on phones set this bit, so they
    won't match any real vendor -- worth calling out rather than showing 'unknown'.
    """
    hexchars = [c for c in (mac or "").upper() if c in "0123456789ABCDEF"]
    if len(hexchars) < 2:
        return False
    try:
        first_octet = int("".join(hexchars[:2]), 16)
        return bool(first_octet & 0x02)
    except ValueError:
        return False


def lookup(mac: str) -> str:
    """Return a human-readable vendor string for a MAC, or a best-effort label."""
    if not mac:
        return "unknown"
    prefix = _normalize(mac)
    if not prefix:
        return "unknown"

    vendor = _load_db().get(prefix)
    if vendor:
        return vendor

    if is_locally_administered(mac):
        return "randomized/private MAC"
    return "unknown"


def enrich_hosts(hosts):
    """Add a 'vendor' key to each discovery host dict (in place) and return it."""
    for h in hosts:
        h["vendor"] = lookup(h.get("mac")) if h.get("mac") else "unknown"
    return hosts
