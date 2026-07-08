"""Persistent history in SQLite.

Tracks devices and their open ports over time so netscope can answer "what's
new since last time?" -- the foundation for change detection and monitoring.
Stored at ~/.netscope/netscope.db by default.
"""

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
    db_path = db_path or DEFAULT_DB
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
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
        CREATE TABLE IF NOT EXISTS events (
            ts     INTEGER NOT NULL,
            type   TEXT NOT NULL,
            detail TEXT
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
    conn.commit()
    return new_ports


def get_known_ports(conn, identity: str):
    rows = conn.execute("SELECT port FROM ports WHERE identity=?", (identity,)).fetchall()
    return {r["port"] for r in rows}


def record_event(conn, etype: str, detail: str = ""):
    conn.execute("INSERT INTO events (ts, type, detail) VALUES (?,?,?)", (_now(), etype, detail))
    conn.commit()


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
