"""Persistent history in SQLite.

Tracks devices and their open ports over time so netscope can answer "what's
new since last time?" -- the foundation for change detection and monitoring.
Stored at ~/.netscope/netscope.db by default.
"""

import json
import os
import sqlite3
import time
import datetime

DEFAULT_DB = os.path.join(os.path.expanduser("~"), ".netscope", "netscope.db")


def _now():
    return int(time.time())


def _iso(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def connect(db_path: str = None):
    db_path = os.path.expanduser(db_path or DEFAULT_DB)
    # dirname() is "" for a bare filename like "audits.db"; makedirs("") raises.
    db_dir = os.path.dirname(os.path.abspath(db_path))
    os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    return conn


def _init_schema(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS devices (
            identity   TEXT PRIMARY KEY,   -- mac if known, else ip
            ip         TEXT,
            mac        TEXT,
            vendor     TEXT,
            hostname   TEXT,
            first_seen INTEGER NOT NULL,
            last_seen  INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ports (
            identity   TEXT NOT NULL,
            port       INTEGER NOT NULL,
            service    TEXT,
            first_seen INTEGER NOT NULL,
            last_seen  INTEGER NOT NULL,
            PRIMARY KEY (identity, port)
        );
        CREATE TABLE IF NOT EXISTS port_scans (
            identity TEXT PRIMARY KEY,   -- device whose ports have been recorded at least once
            ts       INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS events (
            ts     INTEGER NOT NULL,
            type   TEXT NOT NULL,
            detail TEXT
        );
        CREATE TABLE IF NOT EXISTS scans (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            ts      INTEGER NOT NULL,
            subnet  TEXT,
            label   TEXT,
            n_hosts INTEGER,
            summary TEXT            -- JSON: severity counts + risk score
        );
        CREATE TABLE IF NOT EXISTS scan_findings (
            scan_id  INTEGER NOT NULL,
            fid      TEXT NOT NULL,
            severity TEXT,
            category TEXT,
            host     TEXT,
            port     INTEGER,
            title    TEXT,
            detail   TEXT,
            refs     TEXT,          -- ';'-joined
            PRIMARY KEY (scan_id, fid)
        );
        """
    )
    conn.commit()


def _identity(host: dict) -> str:
    return host.get("mac") or host.get("ip")


def upsert_devices(conn, hosts):
    """Insert/update device rows. Returns list of identities that are brand new."""
    now = _now()
    new_ids = []
    for h in hosts:
        ident = _identity(h)
        if not ident:
            continue
        row = conn.execute("SELECT identity FROM devices WHERE identity=?", (ident,)).fetchone()
        if row is None:
            new_ids.append(ident)
            conn.execute(
                "INSERT INTO devices (identity, ip, mac, vendor, hostname, first_seen, last_seen) "
                "VALUES (?,?,?,?,?,?,?)",
                (ident, h.get("ip"), h.get("mac"), h.get("vendor"), h.get("hostname"), now, now),
            )
        else:
            conn.execute(
                "UPDATE devices SET ip=?, mac=COALESCE(?,mac), vendor=COALESCE(?,vendor), "
                "hostname=COALESCE(?,hostname), last_seen=? WHERE identity=?",
                (h.get("ip"), h.get("mac"), h.get("vendor"), h.get("hostname"), now, ident),
            )
    conn.commit()
    return new_ids


def record_ports(conn, identity: str, open_ports):
    """Store open ports for a device. Returns list of newly-seen port numbers."""
    now = _now()
    new_ports = []
    for entry in open_ports:
        port = entry["port"] if isinstance(entry, dict) else entry
        service = entry.get("service") if isinstance(entry, dict) else None
        row = conn.execute(
            "SELECT port FROM ports WHERE identity=? AND port=?", (identity, port)
        ).fetchone()
        if row is None:
            new_ports.append(port)
            conn.execute(
                "INSERT INTO ports (identity, port, service, first_seen, last_seen) VALUES (?,?,?,?,?)",
                (identity, port, service, now, now),
            )
        else:
            conn.execute(
                "UPDATE ports SET last_seen=?, service=COALESCE(?,service) WHERE identity=? AND port=?",
                (now, service, identity, port),
            )
    conn.execute("INSERT OR REPLACE INTO port_scans (identity, ts) VALUES (?,?)", (identity, now))
    conn.commit()
    return new_ports


def has_port_baseline(conn, identity: str) -> bool:
    """True once this device's open ports have been recorded at least once.

    Distinguishes "never port-scanned" (everything is new; don't alert) from
    "scanned before and had no open ports" (a newly opened port *is* news). DBs
    written by older versions have no marker, so existing port rows count too.
    """
    if conn.execute("SELECT 1 FROM port_scans WHERE identity=?", (identity,)).fetchone():
        return True
    return conn.execute("SELECT 1 FROM ports WHERE identity=? LIMIT 1", (identity,)).fetchone() is not None


def get_known_ports(conn, identity: str):
    rows = conn.execute("SELECT port FROM ports WHERE identity=?", (identity,)).fetchall()
    return {r["port"] for r in rows}


def record_event(conn, etype: str, detail: str = ""):
    conn.execute("INSERT INTO events (ts, type, detail) VALUES (?,?,?)", (_now(), etype, detail))
    conn.commit()


def device_count(conn) -> int:
    return conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]


def get_devices(conn):
    rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["first_seen_h"] = _iso(d["first_seen"])
        d["last_seen_h"] = _iso(d["last_seen"])
        out.append(d)
    return out


def get_recent_events(conn, limit: int = 50):
    rows = conn.execute(
        "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall()
    return [{**dict(r), "ts_h": _iso(r["ts"])} for r in rows]


def device_ports(conn, identity: str):
    rows = conn.execute(
        "SELECT port, service, first_seen, last_seen FROM ports WHERE identity=? ORDER BY port",
        (identity,),
    ).fetchall()
    return [{**dict(r), "first_seen_h": _iso(r["first_seen"]), "last_seen_h": _iso(r["last_seen"])} for r in rows]


# ---------- scan snapshots (for baseline diffing) ----------

def save_scan(conn, findings, subnet=None, label=None, n_hosts=0, summary=None):
    """Persist an audit snapshot (a scan row + its findings). Returns the scan id."""
    cur = conn.execute(
        "INSERT INTO scans (ts, subnet, label, n_hosts, summary) VALUES (?,?,?,?,?)",
        (_now(), subnet, label, n_hosts, json.dumps(summary or {})),
    )
    scan_id = cur.lastrowid
    for f in findings:
        conn.execute(
            "INSERT OR REPLACE INTO scan_findings "
            "(scan_id, fid, severity, category, host, port, title, detail, refs) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (scan_id, f["id"], f.get("severity"), f.get("category"), f.get("host"),
             f.get("port"), f.get("title"), f.get("detail"), ";".join(f.get("refs", []))),
        )
    conn.commit()
    return scan_id


def get_scans(conn, limit=20):
    # Tie-break on id so ordering is deterministic when snapshots share a second.
    rows = conn.execute("SELECT * FROM scans ORDER BY ts DESC, id DESC LIMIT ?", (limit,)).fetchall()
    return [{**dict(r), "ts_h": _iso(r["ts"])} for r in rows]


def get_scan(conn, scan_id):
    """One snapshot row by id, or None if there is no such snapshot."""
    r = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return {**dict(r), "ts_h": _iso(r["ts"])} if r else None


def previous_scan(conn, scan_id):
    """The newest snapshot taken before ``scan_id`` of the *same target* (same
    subnet/host), or None. Diffing against a snapshot of a different target would
    report every finding as new/resolved."""
    cur = get_scan(conn, scan_id)
    if not cur:
        return None
    r = conn.execute(
        "SELECT * FROM scans WHERE id < ? AND subnet IS ? ORDER BY id DESC LIMIT 1",
        (scan_id, cur["subnet"]),
    ).fetchone()
    return {**dict(r), "ts_h": _iso(r["ts"])} if r else None


def get_scan_findings(conn, scan_id):
    rows = conn.execute(
        "SELECT * FROM scan_findings WHERE scan_id=?", (scan_id,)
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["refs"] = d["refs"].split(";") if d.get("refs") else []
        d["id"] = d["fid"]          # same key as live findings, so exports are uniform
        out.append(d)
    return out


def diff_scans(conn, old_id, new_id):
    """Compare two saved scans. Returns {added, resolved, unchanged} finding lists,
    keyed by finding id (stable across runs for the same issue).
    """
    old = {f["fid"]: f for f in get_scan_findings(conn, old_id)}
    new = {f["fid"]: f for f in get_scan_findings(conn, new_id)}
    added = [f for fid, f in new.items() if fid not in old]
    resolved = [f for fid, f in old.items() if fid not in new]
    unchanged = [f for fid, f in new.items() if fid in old]
    return {"added": added, "resolved": resolved, "unchanged": unchanged}
