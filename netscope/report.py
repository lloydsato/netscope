"""Generate a self-contained HTML report of the current network state.

Pulls together discovered devices, their open/risky ports and OS guesses, any
passive-capture findings, and the recent event history into one standalone
file (no external assets, renders offline) that reads like a network operations
console rather than a generic table dump.
"""

import html
import datetime

from .utils import RISKY_PORTS

_SEV_COLOR = {
    "critical": "var(--crit)",
    "high": "var(--high)",
    "medium": "var(--med)",
    "low": "var(--muted)",
}


def _esc(s):
    return html.escape(str(s if s is not None else ""))


def _port_chip(entry):
    port = entry["port"] if isinstance(entry, dict) else entry
    service = entry.get("service", "") if isinstance(entry, dict) else ""
    risky = port in RISKY_PORTS
    cls = "chip chip-risk" if risky else "chip"
    title = _esc(RISKY_PORTS[port]) if risky else _esc(service)
    label = f"{port}" + (f"/{_esc(service)}" if service and service != "unknown" else "")
    return f'<span class="{cls}" title="{title}">{label}</span>'


def _device_row(d):
    ports = d.get("ports") or d.get("open_ports") or []
    chips = " ".join(_port_chip(p) for p in ports) or '<span class="chip chip-empty">none seen</span>'
    os_guess = d.get("os_guess") or ""
    vendor = d.get("vendor") or "unknown"
    mac = d.get("mac") or "\u2014"
    hostname = d.get("hostname") or ""
    name_bits = f'<span class="host-ip">{_esc(d.get("ip"))}</span>'
    if hostname:
        name_bits += f'<span class="host-name">{_esc(hostname)}</span>'
    return f"""
      <tr>
        <td class="mono">{name_bits}</td>
        <td class="mono muted">{_esc(mac)}</td>
        <td>{_esc(vendor)}{f'<span class="os-tag">{_esc(os_guess)}</span>' if os_guess else ''}</td>
        <td class="ports">{chips}</td>
      </tr>"""


def _alerts_block(alerts):
    if not alerts:
        return """
      <div class="all-clear">
        <span class="ac-dot"></span> No active threats detected in this snapshot.
      </div>"""
    items = []
    for sev, msg in alerts:
        color = _SEV_COLOR.get(sev, "var(--muted)")
        items.append(f"""
        <li class="alert" style="--sev:{color}">
          <span class="sev-label" style="color:{color}">{_esc(sev)}</span>
          <span class="alert-msg">{_esc(msg)}</span>
        </li>""")
    return f'<ul class="alert-feed">{"".join(items)}</ul>'


def _traffic_block(cap):
    if not cap:
        return ""
    protos = "  ".join(f"{_esc(k)} {v}" for k, v in cap.get("protocol_counts", {}).items()) or "\u2014"
    bw_rows = "".join(
        f'<tr><td class="mono">{_esc(b["host"])}</td><td class="mono num">{_esc(b["human"])}</td></tr>'
        for b in cap.get("top_bandwidth", [])[:6]
    ) or '<tr><td colspan="2" class="muted">no data</td></tr>'
    dns_rows = "".join(
        f'<tr><td class="mono">{_esc(dom)}</td><td class="mono num">{n}</td></tr>'
        for dom, n in cap.get("top_dns", [])[:8]
    ) or '<tr><td colspan="2" class="muted">no queries seen</td></tr>'
    return f"""
    <section class="panel">
      <div class="eyebrow">Traffic snapshot</div>
      <p class="meta-line">{cap.get('total_packets', 0)} packets over {cap.get('duration', 0)}s &middot; {protos}</p>
      <div class="two-col">
        <div>
          <div class="col-head">Top bandwidth</div>
          <table class="mini"><tbody>{bw_rows}</tbody></table>
        </div>
        <div>
          <div class="col-head">Top DNS lookups</div>
          <table class="mini"><tbody>{dns_rows}</tbody></table>
        </div>
      </div>
    </section>"""


def _events_block(events):
    if not events:
        return ""
    rows = "".join(
        f'<tr><td class="mono muted">{_esc(e.get("ts_h",""))}</td>'
        f'<td class="ev-type">{_esc(e.get("type",""))}</td>'
        f'<td>{_esc(e.get("detail",""))}</td></tr>'
        for e in events[:20]
    )
    return f"""
    <section class="panel">
      <div class="eyebrow">Recent activity</div>
      <table class="mini events"><tbody>{rows}</tbody></table>
    </section>"""


def render(devices, capture_summary=None, events=None, subnet=None, title="netscope report"):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alerts = capture_summary.get("alerts", []) if capture_summary else []

    # headline stats
    n_dev = len(devices)
    exposed = sum(len(d.get("ports") or d.get("open_ports") or []) for d in devices)
    n_alerts = len(alerts)
    crit = sum(1 for s, _ in alerts if s in ("critical", "high"))

    device_rows = "".join(_device_row(d) for d in devices) or \
        '<tr><td colspan="4" class="muted">No devices discovered.</td></tr>'

    status_class = "danger" if crit else ("watch" if n_alerts else "ok")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>
  :root {{
    --bg:#0e1620; --surface:#161f2b; --surface-2:#1c2836; --line:#28374a;
    --text:#e7eef5; --muted:#7d8fa1; --accent:#43d8c4;
    --crit:#ff5d6c; --high:#ff9153; --med:#ffce5c;
    --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
    --sans: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  }}
  * {{ box-sizing:border-box; }}
  body {{
    margin:0; background:var(--bg); color:var(--text);
    font-family:var(--sans); line-height:1.5;
    -webkit-font-smoothing:antialiased;
  }}
  .wrap {{ max-width:1040px; margin:0 auto; padding:32px 24px 64px; }}

  header {{
    position:relative; border:1px solid var(--line); border-radius:14px;
    background:
      linear-gradient(180deg, rgba(67,216,196,0.06), transparent 60%),
      repeating-linear-gradient(90deg, transparent 0 38px, rgba(67,216,196,0.04) 38px 39px),
      var(--surface);
    padding:26px 28px; overflow:hidden;
  }}
  .wordmark {{
    font-family:var(--mono); font-weight:600; letter-spacing:-0.5px;
    font-size:26px; margin:0; display:flex; align-items:center; gap:12px;
  }}
  .wordmark .beacon {{
    width:9px; height:9px; border-radius:50%; background:var(--accent);
    box-shadow:0 0 0 0 rgba(67,216,196,0.6); animation:pulse 2.4s ease-out infinite;
  }}
  @keyframes pulse {{
    0% {{ box-shadow:0 0 0 0 rgba(67,216,196,0.5); }}
    70% {{ box-shadow:0 0 0 10px rgba(67,216,196,0); }}
    100% {{ box-shadow:0 0 0 0 rgba(67,216,196,0); }}
  }}
  .sub {{ color:var(--muted); font-family:var(--mono); font-size:13px; margin-top:6px; }}
  .statline {{ display:flex; gap:28px; margin-top:22px; flex-wrap:wrap; }}
  .stat {{ display:flex; flex-direction:column; gap:2px; }}
  .stat .n {{ font-family:var(--mono); font-size:30px; font-weight:600; line-height:1; }}
  .stat .l {{ font-size:11px; text-transform:uppercase; letter-spacing:1.5px; color:var(--muted); }}
  .stat.danger .n {{ color:var(--crit); }}
  .stat.watch .n {{ color:var(--med); }}
  .stat.ok .n {{ color:var(--accent); }}

  .eyebrow {{
    font-size:11px; text-transform:uppercase; letter-spacing:2px;
    color:var(--muted); margin:0 0 14px; font-weight:600;
  }}
  section.panel {{
    margin-top:26px; border:1px solid var(--line); border-radius:14px;
    background:var(--surface); padding:22px 24px;
  }}

  .alert-feed {{ list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:10px; }}
  .alert {{
    border-left:3px solid var(--sev); background:var(--surface-2);
    padding:11px 14px; border-radius:0 8px 8px 0; display:flex; gap:14px; align-items:baseline;
  }}
  .sev-label {{
    font-family:var(--mono); font-size:11px; text-transform:uppercase;
    letter-spacing:1px; font-weight:700; min-width:64px;
  }}
  .alert-msg {{ font-size:14px; }}
  .all-clear {{
    display:flex; align-items:center; gap:10px; color:var(--muted);
    font-family:var(--mono); font-size:14px; padding:6px 0;
  }}
  .ac-dot {{ width:8px; height:8px; border-radius:50%; background:var(--accent); }}

  table {{ width:100%; border-collapse:collapse; }}
  thead th {{
    text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:1px;
    color:var(--muted); font-weight:600; padding:0 12px 10px; border-bottom:1px solid var(--line);
  }}
  tbody td {{ padding:12px; border-bottom:1px solid rgba(40,55,74,0.5); vertical-align:top; font-size:14px; }}
  tbody tr:last-child td {{ border-bottom:none; }}
  .mono {{ font-family:var(--mono); }}
  .muted {{ color:var(--muted); }}
  .num {{ text-align:right; }}
  .host-ip {{ display:block; }}
  .host-name {{ display:block; font-size:12px; color:var(--muted); }}
  .os-tag {{
    display:inline-block; margin-left:8px; font-family:var(--mono); font-size:11px;
    color:var(--accent); border:1px solid rgba(67,216,196,0.35); border-radius:4px; padding:1px 6px;
  }}
  .ports {{ display:flex; flex-wrap:wrap; gap:6px; }}
  .chip {{
    font-family:var(--mono); font-size:12px; padding:2px 8px; border-radius:5px;
    background:var(--surface-2); border:1px solid var(--line); color:var(--text); white-space:nowrap;
  }}
  .chip-risk {{ border-color:var(--crit); color:var(--crit); background:rgba(255,93,108,0.08); }}
  .chip-empty {{ color:var(--muted); border-style:dashed; }}

  .two-col {{ display:grid; grid-template-columns:1fr 1fr; gap:26px; margin-top:8px; }}
  .col-head {{ font-family:var(--mono); font-size:12px; color:var(--muted); margin-bottom:6px; }}
  table.mini td {{ padding:6px 8px; font-size:13px; border-bottom:1px solid rgba(40,55,74,0.4); }}
  .meta-line {{ font-family:var(--mono); font-size:13px; color:var(--muted); margin:0 0 14px; }}
  .ev-type {{ font-family:var(--mono); font-size:12px; color:var(--accent); }}

  footer {{ margin-top:32px; color:var(--muted); font-size:12px; font-family:var(--mono); text-align:center; }}

  @media (max-width:640px) {{
    .two-col {{ grid-template-columns:1fr; }}
    .statline {{ gap:18px; }}
    thead {{ display:none; }}
    tbody td {{ display:block; border:none; padding:4px 0; }}
    tbody tr {{ display:block; padding:12px 0; border-bottom:1px solid var(--line); }}
  }}
  @media (prefers-reduced-motion: reduce) {{ .beacon {{ animation:none; }} }}
</style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1 class="wordmark"><span class="beacon"></span>netscope</h1>
      <div class="sub">{_esc(subnet or "network")} &middot; generated {now}</div>
      <div class="statline">
        <div class="stat"><span class="n">{n_dev}</span><span class="l">devices</span></div>
        <div class="stat"><span class="n">{exposed}</span><span class="l">open ports</span></div>
        <div class="stat {status_class}"><span class="n">{n_alerts}</span><span class="l">alerts</span></div>
      </div>
    </header>

    <section class="panel">
      <div class="eyebrow">Threat feed</div>
      {_alerts_block(alerts)}
    </section>

    <section class="panel">
      <div class="eyebrow">Devices &middot; {n_dev}</div>
      <table>
        <thead><tr><th>Address</th><th>MAC</th><th>Vendor / OS</th><th>Open ports</th></tr></thead>
        <tbody>{device_rows}</tbody>
      </table>
    </section>

    {_traffic_block(capture_summary)}
    {_events_block(events)}

    <footer>netscope &middot; for use on networks you own or are authorized to assess</footer>
  </div>
</body>
</html>"""


def write_report(path, devices, capture_summary=None, events=None, subnet=None):
    htmldoc = render(devices, capture_summary, events, subnet)
    with open(path, "w", encoding="utf-8") as f:
        f.write(htmldoc)
    return path
