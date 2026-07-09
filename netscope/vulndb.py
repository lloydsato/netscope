"""Offline vulnerability correlation.

Given a product + version extracted from a service banner (see
``fingerprint.parse_service``), match it against a bundled snapshot of
well-known CVEs and weak-default advisories. Works fully offline -- the same
philosophy as the bundled OUI database in ``oui.py``.

The bundled data lives in ``data/vulns.json.gz`` and is a curated, deliberately
small list (netscope is a defensive auditing aid, not a substitute for a full
vulnerability scanner). Each record::

    {
      "product":     "openssh",
      "affected":    "<7.7",          # version predicate (see _version_match)
      "cve":         "CVE-2018-15473",
      "cvss":        5.3,
      "severity":    "medium",         # optional; derived from cvss if absent
      "title":       "OpenSSH username enumeration",
      "description": "...",
      "ref":         "https://nvd.nist.gov/vuln/detail/CVE-2018-15473"
    }

Regenerate the snapshot with ``python scripts/build_vulndb.py``.
"""

import functools
import gzip
import json
import os
import re

_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "vulns.json.gz")


@functools.lru_cache(maxsize=1)
def _load_db():
    try:
        with gzip.open(_DATA_PATH, "rb") as f:
            return json.loads(f.read().decode("utf-8"))
    except Exception:
        return {"records": [], "weak_defaults": {}}


def _version_tuple(v: str):
    """Split a version like '7.2p2' or '1.4.10' into a comparable tuple.

    Every run of digits becomes one component, in order, so patch-level suffixes
    are preserved: '7.2p2' -> (7, 2, 2), '9.3p1' -> (9, 3, 1), '2.4.49' ->
    (2, 4, 49). This keeps boundary comparisons (e.g. 9.3p1 < 9.3p2) correct.
    """
    parts = [int(x) for x in re.findall(r"\d+", str(v))]
    return tuple(parts) if parts else (0,)


def _cmp(a, b):
    ta, tb = _version_tuple(a), _version_tuple(b)
    # pad to equal length
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def _version_match(version: str, predicate: str) -> bool:
    """Evaluate a version predicate. Supported forms:

    - "*"                 any version
    - "<7.7"              less than
    - "<=1.2.3"           less than or equal
    - ">=3.0,<3.4"        comma-joined AND of clauses
    - "==2.4.49" / "2.4.49"  exact match
    """
    if not version:
        # No version advertised -> we can't confirm the range; be conservative
        # and only match wildcard predicates.
        return predicate.strip() == "*"
    predicate = predicate.strip()
    if predicate == "*":
        return True
    for clause in predicate.split(","):
        clause = clause.strip()
        m = re.match(r"(<=|>=|<|>|==)?\s*(.+)", clause)
        if not m:
            return False
        op, target = m.group(1) or "==", m.group(2).strip()
        c = _cmp(version, target)
        ok = (
            (op == "<" and c < 0) or (op == "<=" and c <= 0) or
            (op == ">" and c > 0) or (op == ">=" and c >= 0) or
            (op == "==" and c == 0)
        )
        if not ok:
            return False
    return True


def match(product: str, version: str = ""):
    """Return the list of vuln records affecting ``product`` at ``version``.

    Records with severity absent get one derived from CVSS. Ordered by CVSS
    descending so the worst shows first.
    """
    if not product:
        return []
    product = product.lower()
    db = _load_db()
    out = []
    for rec in db.get("records", []):
        if rec.get("product", "").lower() != product:
            continue
        if _version_match(version, rec.get("affected", "*")):
            r = dict(rec)
            if not r.get("severity"):
                r["severity"] = _severity_from_cvss(r.get("cvss"))
            out.append(r)
    out.sort(key=lambda r: -(r.get("cvss") or 0))
    return out


def weak_default(product: str):
    """Return a weak-default advisory string for a product, if any (e.g. Redis /
    MongoDB historically shipping with no authentication)."""
    if not product:
        return None
    return _load_db().get("weak_defaults", {}).get(product.lower())


def _severity_from_cvss(cvss):
    if cvss is None:
        return "medium"
    try:
        c = float(cvss)
    except (TypeError, ValueError):
        return "medium"
    if c >= 9.0:
        return "critical"
    if c >= 7.0:
        return "high"
    if c >= 4.0:
        return "medium"
    if c > 0:
        return "low"
    return "info"
