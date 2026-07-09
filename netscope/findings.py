"""Unified findings model, risk scoring, and machine-readable export.

Every risk source in netscope -- risky ports, CVE matches, TLS/certificate
issues, weak/default-auth exposure, and passive traffic threats -- is normalised
into a single ``Finding`` shape so downstream code (scoring, HTML report, and
exporters) only has to understand one thing.

A ``Finding`` is a plain dict::

    {
      "id":       "stable-slug",       # dedupe key, category+host+port+detail
      "category": "cve" | "tls" | ...  # what kind of check produced it
      "severity": "critical" | "high" | "medium" | "low" | "info",
      "title":    "short headline",
      "host":     "192.168.1.10",      # subject host (or "" for network-wide)
      "port":     22,                   # int or None
      "detail":   "longer explanation",
      "evidence": "the banner / cert line / cipher we observed",
      "refs":     ["CVE-2018-15473", "https://..."],
      "cvss":     7.5,                  # float or None
    }

Exporters cover the formats auditors and CI actually consume: JSON, NDJSON,
CSV, and SARIF 2.1.0 (so findings can be uploaded as code-scanning alerts).
"""

import csv
import hashlib
import io
import json
import math

SEVERITIES = ("critical", "high", "medium", "low", "info")

_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Weight each severity contributes to a 0-100 risk score.
_SEV_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}

# SARIF result level per severity (SARIF only has error/warning/note/none).
_SARIF_LEVEL = {
    "critical": "error", "high": "error", "medium": "warning",
    "low": "note", "info": "none",
}


def make_finding(category, severity, title, host="", port=None, detail="",
                 evidence="", refs=None, cvss=None):
    """Build a normalised finding dict with a stable, content-derived id."""
    severity = severity if severity in _SEV_RANK else "info"
    refs = list(refs) if refs else []
    basis = f"{category}|{host}|{port}|{title}|{detail}"
    fid = hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:12]
    return {
        "id": fid,
        "category": category,
        "severity": severity,
        "title": title,
        "host": host,
        "port": port,
        "detail": detail,
        "evidence": evidence,
        "refs": refs,
        "cvss": cvss,
    }


def severity_rank(finding):
    """Sort key: critical first (0), info last (4)."""
    return _SEV_RANK.get(finding.get("severity"), len(SEVERITIES))


def sort_findings(findings):
    """Return findings ordered by severity, then host, then port."""
    return sorted(
        findings,
        key=lambda f: (severity_rank(f), f.get("host") or "", f.get("port") or 0),
    )


def dedupe(findings):
    """Drop findings sharing the same id (same category/host/port/title/detail)."""
    seen = {}
    for f in findings:
        seen.setdefault(f["id"], f)
    return list(seen.values())


def severity_counts(findings):
    """Return {severity: count} across all severities (zeros included)."""
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    return counts


def risk_score(findings):
    """Roll findings into a single 0-100 risk score.

    A saturating function of weighted severity counts: one critical already puts
    a host well into the red, while a long tail of lows accumulates slowly. 0
    means nothing found; 100 means "stop reading this number and go look".
    """
    raw = sum(_SEV_WEIGHT.get(f.get("severity", "info"), 0) for f in findings)
    if raw <= 0:
        return 0
    # Saturating curve: 100 * (1 - e^(-raw/60)). ~28 at one high, ~100 by ~3 crit.
    return int(round(100 * (1 - math.exp(-raw / 60.0))))


def by_host(findings):
    """Group findings by host -> [findings], each list severity-sorted."""
    groups = {}
    for f in findings:
        groups.setdefault(f.get("host") or "network", []).append(f)
    return {h: sort_findings(fs) for h, fs in groups.items()}


def host_risk_scores(findings):
    """Return {host: risk_score} for every host that has findings."""
    return {h: risk_score(fs) for h, fs in by_host(findings).items()}


# ---------- exporters ----------

def to_json(findings, meta=None, indent=2):
    payload = {"meta": meta or {}, "findings": sort_findings(findings)}
    return json.dumps(payload, indent=indent, default=str)


def to_ndjson(findings):
    """Newline-delimited JSON: one finding per line (stream/CI friendly)."""
    return "\n".join(json.dumps(f, default=str) for f in sort_findings(findings))


_CSV_COLUMNS = ["severity", "category", "host", "port", "title", "detail", "refs", "cvss"]


def to_csv(findings):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(_CSV_COLUMNS)
    for f in sort_findings(findings):
        w.writerow([
            f.get("severity", ""), f.get("category", ""), f.get("host", ""),
            f.get("port", "") if f.get("port") is not None else "",
            f.get("title", ""), f.get("detail", ""),
            ";".join(f.get("refs", [])), f.get("cvss", "") if f.get("cvss") is not None else "",
        ])
    return buf.getvalue()


def to_sarif(findings, tool_version="0.3.0"):
    """Minimal SARIF 2.1.0. One run, one rule per finding category, one result
    per finding. Uploadable to GitHub code scanning and other SARIF consumers.
    """
    findings = sort_findings(findings)
    categories = {}
    for f in findings:
        categories.setdefault(f["category"], f["title"])

    rules = [
        {
            "id": cat,
            "name": cat.replace("-", " ").title().replace(" ", ""),
            "shortDescription": {"text": f"netscope {cat} finding"},
        }
        for cat in sorted(categories)
    ]

    results = []
    for f in findings:
        loc_text = f.get("host") or "network"
        if f.get("port"):
            loc_text = f"{loc_text}:{f['port']}"
        msg = f.get("detail") or f.get("title") or ""
        result = {
            "ruleId": f["category"],
            "level": _SARIF_LEVEL.get(f.get("severity"), "warning"),
            "message": {"text": msg},
            "properties": {
                "severity": f.get("severity"),
                "host": f.get("host"),
                "port": f.get("port"),
                "refs": f.get("refs", []),
                "cvss": f.get("cvss"),
                "evidence": f.get("evidence", ""),
            },
            "locations": [{
                "logicalLocations": [{"fullyQualifiedName": loc_text}]
            }],
        }
        results.append(result)

    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "netscope",
                "informationUri": "https://github.com/lloydsato/netscope",
                "version": tool_version,
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, default=str)


EXPORTERS = {
    "json": to_json,
    "ndjson": lambda findings, meta=None: to_ndjson(findings),
    "csv": lambda findings, meta=None: to_csv(findings),
    "sarif": lambda findings, meta=None: to_sarif(findings),
}


def export(findings, fmt, meta=None):
    """Render findings in one of the supported formats ('json'/'ndjson'/'csv'/'sarif')."""
    fmt = (fmt or "json").lower()
    if fmt not in EXPORTERS:
        raise ValueError(f"Unknown export format '{fmt}'. Choose from {sorted(EXPORTERS)}.")
    if fmt == "json":
        return to_json(findings, meta=meta)
    return EXPORTERS[fmt](findings, meta)


# ---------- adapters: turn raw check output into Findings ----------

def from_risky_ports(host, open_ports, risky_map):
    """Risky open ports (port-number heuristics) -> findings."""
    out = []
    for entry in open_ports:
        port = entry["port"] if isinstance(entry, dict) else entry
        note = risky_map.get(port)
        if not note:
            continue
        service = entry.get("service", "") if isinstance(entry, dict) else ""
        out.append(make_finding(
            "exposed-port", "medium",
            f"Risky port {port}/{service} exposed",
            host=host, port=port, detail=note, evidence=f"{port}/{service} open",
        ))
    return out


def from_cve_matches(host, port, service, matches):
    """vulndb.match() output -> findings."""
    out = []
    for m in matches:
        cvss = m.get("cvss")
        sev = m.get("severity") or _severity_from_cvss(cvss)
        refs = [r for r in [m.get("cve"), m.get("ref")] if r]
        title = m.get("title") or m.get("cve") or "Known vulnerability"
        out.append(make_finding(
            "cve", sev, title, host=host, port=port,
            detail=m.get("description", ""), evidence=f"{service}", refs=refs, cvss=cvss,
        ))
    return out


def from_tls(host, port, tls_findings):
    """tlsaudit.inspect() findings (list of {severity,title,detail,evidence}) -> findings."""
    out = []
    for t in tls_findings:
        out.append(make_finding(
            "tls", t.get("severity", "medium"), t.get("title", "TLS issue"),
            host=host, port=port, detail=t.get("detail", ""),
            evidence=t.get("evidence", ""), refs=t.get("refs", []),
        ))
    return out


def from_probes(probe_findings):
    """probes.* findings -> findings (each already carries host/port/severity)."""
    out = []
    for p in probe_findings:
        out.append(make_finding(
            p.get("category", "weak-auth"), p.get("severity", "high"),
            p.get("title", "Weak/default auth exposure"),
            host=p.get("host", ""), port=p.get("port"),
            detail=p.get("detail", ""), evidence=p.get("evidence", ""),
            refs=p.get("refs", []),
        ))
    return out


def from_capture_alerts(alerts):
    """capture summary 'alerts' (list of (severity, message)) -> findings."""
    out = []
    for sev, msg in alerts:
        # The message prefix (e.g. "ARP:", "BEACON:") makes a good category.
        cat = "traffic"
        if ":" in msg:
            cat = msg.split(":", 1)[0].strip().lower() or "traffic"
        out.append(make_finding(
            f"traffic-{cat}", sev if sev in _SEV_RANK else "medium",
            msg[:80], detail=msg,
        ))
    return out


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
