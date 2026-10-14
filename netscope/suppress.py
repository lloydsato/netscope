"""Accepted-risk handling: suppress known findings, and gate CI on what's left.

A suppression file lists findings you have reviewed and accepted. Matching is by
the stable finding ``id`` (what ``diff`` and SARIF already use) or by
``category`` / ``host`` / ``port`` selectors. Suppressed findings are *never*
silently dropped: callers get them back separately so they can be counted and
listed, and a rule can carry an ``expires`` date so an exception is revisited
instead of living forever.

Two file formats, chosen by content:

JSON (a list, or ``{"suppressions": [...]}``)::

    [{"id": "a1b2c3d4e5f6", "reason": "lab router, replacing in Q4", "expires": "2026-12-31"},
     {"category": "tls", "host": "10.0.0.*", "reason": "internal CA pending"}]

Line format (``#`` starts the reason; ``expires=`` is optional)::

    a1b2c3d4e5f6                 expires=2026-12-31   # lab router
    tls:10.0.0.*:443                                  # category:host:port, '*' = any

Every rule needs at least one selector, so an empty/blank rule can never
suppress everything.
"""

import datetime
import fnmatch
import json
import re

from . import findings as fmod


class SuppressionError(ValueError):
    """The suppression file is unreadable or malformed."""


_ID_RE = re.compile(r"^[0-9a-f]{12}$")


def _parse_date(value, where):
    try:
        return datetime.date.fromisoformat(str(value))
    except ValueError:
        raise SuppressionError(f"{where}: invalid expires date {value!r} (use YYYY-MM-DD)") from None


def _make_rule(where, id=None, category=None, host=None, port=None, reason="", expires=None):
    rule = {"id": None, "category": None, "host": None, "port": None,
            "reason": str(reason or "").strip(), "expires": None, "where": where}
    if id not in (None, "", "*"):
        id = str(id).strip().lower()
        if not _ID_RE.match(id):
            raise SuppressionError(f"{where}: invalid finding id {id!r} (expected 12 hex characters)")
        rule["id"] = id
    for key, val in (("category", category), ("host", host)):
        if val not in (None, "", "*"):
            rule[key] = str(val).strip()
    if port not in (None, "", "*"):
        try:
            rule["port"] = int(port)
        except (TypeError, ValueError):
            raise SuppressionError(f"{where}: invalid port {port!r}") from None
    if expires not in (None, ""):
        rule["expires"] = _parse_date(expires, where)
    if not any(rule[k] is not None for k in ("id", "category", "host", "port")):
        raise SuppressionError(f"{where}: rule has no selector (id, category, host or port); "
                               "refusing a rule that would match every finding")
    return rule


def _parse_json(text, source):
    try:
        data = json.loads(text)
    except ValueError as e:
        raise SuppressionError(f"{source}: invalid JSON: {e}") from None
    if isinstance(data, dict):
        data = data.get("suppressions")
    if not isinstance(data, list):
        raise SuppressionError(f"{source}: expected a list of rules or {{\"suppressions\": [...]}}")
    rules = []
    allowed = {"id", "category", "host", "port", "reason", "expires"}
    for i, item in enumerate(data, 1):
        where = f"{source}: rule {i}"
        if not isinstance(item, dict):
            raise SuppressionError(f"{where}: expected an object")
        unknown = set(item) - allowed
        if unknown:
            raise SuppressionError(f"{where}: unknown key(s) {sorted(unknown)}")
        rules.append(_make_rule(where, **item))
    return rules


def _parse_lines(text, source):
    rules = []
    for n, raw in enumerate(text.splitlines(), 1):
        body, _, reason = raw.partition("#")
        body = body.strip()
        if not body:
            continue
        where = f"{source}:{n}"
        tokens = body.split()
        expires = None
        selector = []
        for t in tokens:
            if t.lower().startswith("expires="):
                expires = t.split("=", 1)[1]
            else:
                selector.append(t)
        if len(selector) != 1:
            raise SuppressionError(f"{where}: expected one selector (an id or category:host:port)")
        sel = selector[0]
        if ":" in sel:
            parts = sel.split(":")
            if len(parts) != 3:
                raise SuppressionError(f"{where}: selector {sel!r} must be category:host:port")
            rules.append(_make_rule(where, category=parts[0], host=parts[1], port=parts[2],
                                    reason=reason, expires=expires))
        else:
            rules.append(_make_rule(where, id=sel, reason=reason, expires=expires))
    return rules


def load_rules(path):
    """Read a suppression file -> list of rule dicts. Raises SuppressionError."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
    except (OSError, UnicodeError) as e:
        raise SuppressionError(f"cannot read suppression file {path}: {e}") from None
    if text.lstrip().startswith(("[", "{")):
        return _parse_json(text, path)
    return _parse_lines(text, path)


def _matches(rule, finding):
    if rule["id"] is not None and finding.get("id") != rule["id"]:
        return False
    if rule["category"] is not None and not fnmatch.fnmatchcase(finding.get("category") or "", rule["category"]):
        return False
    if rule["host"] is not None and not fnmatch.fnmatchcase(finding.get("host") or "", rule["host"]):
        return False
    if rule["port"] is not None and finding.get("port") != rule["port"]:
        return False
    return True


def apply_suppressions(findings, rules, today=None):
    """Split findings -> (active, suppressed, expired_rules).

    Each suppressed finding is a copy carrying ``suppression`` =
    ``{"reason", "rule", "expires"}``. Rules past their ``expires`` date do not
    apply and are returned in ``expired_rules`` so the caller can warn about them.
    """
    today = today or datetime.date.today()
    live = [r for r in rules if r["expires"] is None or r["expires"] >= today]
    expired = [r for r in rules if r["expires"] is not None and r["expires"] < today]
    active, suppressed = [], []
    for f in findings:
        rule = next((r for r in live if _matches(r, f)), None)
        if rule is None:
            active.append(f)
        else:
            suppressed.append(dict(f, suppression={
                "reason": rule["reason"], "rule": rule["where"],
                "expires": rule["expires"].isoformat() if rule["expires"] else None,
            }))
    return active, suppressed, expired


def apply_to_results(results, active_ids):
    """Drop suppressed findings from per-host deep-audit results (in place) and
    re-score each host, so summaries and --json agree with the active set."""
    for r in results:
        before = len(r.get("findings", []))
        r["findings"] = [f for f in r.get("findings", []) if f["id"] in active_ids]
        r["risk_score"] = fmod.risk_score(r["findings"])
        r["suppressed_count"] = before - len(r["findings"])
    return results


def exceeds(findings, level):
    """True if any finding is at or above severity ``level`` (None = never)."""
    if not level:
        return False
    limit = fmod.SEVERITIES.index(level)
    return any(fmod.severity_rank(f) <= limit for f in findings)
