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
import warnings

_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "vulns.json.gz")


@functools.lru_cache(maxsize=1)
def _load_db():
    try:
        with gzip.open(_DATA_PATH, "rb") as f:
            return json.loads(f.read().decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        # Failing silently would make every audit look clean; say so once.
        warnings.warn(
            f"netscope: could not load the bundled vulnerability database "
            f"({_DATA_PATH}: {e}); CVE correlation is DISABLED for this run.",
            RuntimeWarning, stacklevel=2,
        )
        return {"records": [], "weak_defaults": {}}


_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")

# Words that mark a version as *older* than the bare release ('2.0rc1' < '2.0').
# Any other letter run is a post-release marker ('1.3.5a' > '1.3.5', '7.2p2' >
# '7.2'), which is the convention of the services netscope fingerprints
# (OpenSSH 'p', ProFTPD/OpenSSL trailing letters).
_PRERELEASE_RANK = {
    "dev": -5, "snapshot": -5, "nightly": -5, "alpha": -4, "beta": -3,
    "pre": -2, "preview": -2, "rc": -1,
}


def _letter_rank(word: str) -> int:
    word = word.lower()
    if word in _PRERELEASE_RANK:
        return _PRERELEASE_RANK[word]
    rank = 0
    for ch in word:
        rank = rank * 27 + (ord(ch) - 96 if "a" <= ch <= "z" else 0)
    return rank


def _version_tuple(v: str):
    """Split a version like '7.2p2' or '1.3.5a' into a comparable tuple.

    Digit runs become integers and letter runs become a rank, in order, so
    suffixes are preserved and ordered sensibly: '7.2p2' < '7.2p3', '1.3.5' <
    '1.3.5a' < '1.3.5b', and '2.0rc1' < '2.0'. Shorter versions are treated as
    zero-padded by ``_cmp``.
    """
    parts = []
    for tok in _TOKEN_RE.findall(str(v)):
        parts.append(int(tok) if tok.isdigit() else _letter_rank(tok))
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
    - "<1.3.8 || >=1.4.0,<1.4.3"  '||'-joined alternatives (any may match), for
      products whose affected releases span disjoint branches

    Prefer an exclusive upper bound at the next release ('<7.8') over an
    inclusive one ('<=7.7'): suffixed versions such as '7.7p1' sort *after*
    '7.7', so '<=7.7' would wrongly exclude them.
    """
    predicate = (predicate or "").strip()
    if not version:
        # No version advertised -> we can't confirm the range; be conservative
        # and only match wildcard predicates.
        return predicate == "*"
    if predicate == "*":
        return True
    return any(_clauses_match(version, alt) for alt in predicate.split("||"))


def _clauses_match(version: str, predicate: str) -> bool:
    """Evaluate one comma-joined AND of clauses against ``version``."""
    predicate = predicate.strip()
    if not predicate:
        return False
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
