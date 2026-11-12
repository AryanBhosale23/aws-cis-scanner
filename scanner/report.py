"""Turns the evidence records into one self-contained HTML page (no internet, no JavaScript)."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from html import escape
from pathlib import Path

from scanner.evidence import mask_account
from scanner.models import CIS_VERSION, Context, Evidence, Status, worst_status
from scanner.runner import check_order

STYLE = """
:root { --bg:#f7f7f5; --card:#fff; --text:#1c1c1a; --muted:#6b6b66; --line:#e2e2dc;
  --pass:#1a7f4b; --fail:#c0392b; --error:#b7791f; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#161614; --card:#201f1d; --text:#ecebe6; --muted:#a09f98; --line:#34332f;
    --pass:#4cc38a; --fail:#ff7b6b; --error:#e3b341; } }
body { margin:0; padding:24px 16px; background:var(--bg); color:var(--text);
  font:15px/1.5 system-ui, sans-serif; }
main { max-width:960px; margin:0 auto; }
h1 { margin:0 0 4px; font-size:26px; } h2 { margin-top:36px; font-size:19px; }
h3 { margin:0 0 4px; font-size:16px; }
.muted { color:var(--muted); font-size:13px; }
.tiles { display:flex; flex-wrap:wrap; gap:12px; margin:20px 0; }
.tile { flex:1 1 150px; background:var(--card); border:1px solid var(--line);
  border-radius:10px; padding:14px 16px; }
.tile b { display:block; font-size:22px; }
table { width:100%; border-collapse:collapse; background:var(--card);
  border:1px solid var(--line); border-radius:10px; overflow:hidden; }
td:first-child { white-space:nowrap; }
th, td { text-align:left; padding:8px 12px; border-bottom:1px solid var(--line);
  font-size:14px; vertical-align:top; }
th { color:var(--muted); font-weight:600; }
.badge { display:inline-block; padding:1px 8px; border-radius:999px; font-size:12px;
  font-weight:700; color:#fff; }
.badge.pass { background:var(--pass); } .badge.fail { background:var(--fail); }
.badge.error { background:var(--error); }
section { background:var(--card); border:1px solid var(--line); border-radius:10px;
  padding:16px; margin:14px 0; }
.rec { border-top:1px solid var(--line); padding:10px 0; }
pre { margin:6px 0 0; padding:10px; background:var(--bg); border-radius:6px;
  overflow-x:auto; font-size:12.5px; }
code { word-break:break-all; }
a { color:inherit; }
"""


def _badge(status: str) -> str:
    return f'<span class="badge {status.lower()}">{status}</span>'


def _group_by_check(results: list[Evidence]) -> dict[str, list[Evidence]]:
    groups: dict[str, list[Evidence]] = defaultdict(list)
    for r in results:
        groups[r.check_id].append(r)
    return {check_id: groups[check_id] for check_id in sorted(groups, key=check_order)}


def _cis_number(r: Evidence) -> str:
    """'CIS AWS Foundations Benchmark v7.1.0, 2.5' -> '2.5' (the version is shown once, on top)."""
    return r.controls.cis.removeprefix(f"{CIS_VERSION}, ")


def _controls_line(r: Evidence) -> str:
    c = r.controls
    parts = [
        f"CIS {_cis_number(r)}",
        f"NIST {c.nist_800_53_r5}",
        f"ISO 27001 {c.iso_27001_2022}",
        f"SOC 2 {c.soc2}",
    ]
    return " &middot; ".join(escape(p) for p in parts)


def _record(r: Evidence) -> str:
    detail = json.dumps(r.evidence, indent=2, default=str)
    return (
        f'<div class="rec">{_badge(r.status)} <code>{escape(r.resource)}</code>'
        f"<pre>{escape(detail)}</pre></div>"
    )


def _overview_row(check_id: str, records: list[Evidence]) -> str:
    first = records[0]
    not_passing = sum(1 for r in records if r.status is not Status.PASS)
    return (
        f'<tr><td><a href="#{escape(check_id)}">{escape(check_id)}</a></td>'
        f"<td>{escape(first.title)}</td>"
        f"<td>{_badge(worst_status(records))}</td>"
        f"<td>{not_passing} of {len(records)}</td>"
        f"<td>{escape(_cis_number(first))}</td></tr>"
    )


def _section(check_id: str, records: list[Evidence]) -> str:
    first = records[0]
    bad = [r for r in records if r.status is not Status.PASS]
    good = [r for r in records if r.status is Status.PASS]
    html = [
        f'<section id="{escape(check_id)}">',
        f"<h3>{escape(check_id)} &middot; {escape(first.title)} "
        f"{_badge(worst_status(records))}</h3>",
        f'<div class="muted">{_controls_line(first)}</div>',
    ]
    html.extend(_record(r) for r in bad)
    if bad:
        html.append(f"<p><b>How to fix:</b> {escape(first.remediation)}</p>")
    if good:
        html.append(
            f"<details><summary>{len(good)} passing resource(s)</summary>"
            f"{''.join(_record(r) for r in good)}</details>"
        )
    html.append("</section>")
    return "".join(html)


def render_report(ctx: Context, results: list[Evidence]) -> str:
    groups = _group_by_check(results)
    counts = Counter(r.status for r in results)
    checks_passed = sum(1 for g in groups.values() if worst_status(g) is Status.PASS)
    scanned_at = max((r.timestamp for r in results), default="")

    if results:
        tiles = (
            '<div class="tiles">'
            f'<div class="tile"><b>{checks_passed} of {len(groups)} checks passed</b></div>'
            f'<div class="tile"><b>{counts[Status.PASS]} passed, {counts[Status.FAIL]} failed, '
            f"{counts[Status.ERROR]} error</b>records</div></div>"
        )
        table = (
            "<h2>All checks</h2><table><tr><th>ID</th><th>Check</th><th>Status</th>"
            "<th>Not passing</th><th>CIS</th></tr>"
            + "".join(_overview_row(cid, recs) for cid, recs in groups.items())
            + "</table>"
        )
        details = "<h2>Details and evidence</h2>" + "".join(
            _section(cid, recs) for cid, recs in groups.items()
        )
        body = tiles + table + details
    else:
        body = "<p>No results: no check ran.</p>"

    page = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>AWS CIS scan report</title><style>{STYLE}</style></head><body><main>"
        "<h1>AWS CIS scan report</h1>"
        f'<div class="muted">Account {mask_account(ctx.account_id)} &middot; region '
        f"{escape(ctx.region)} &middot; scanned {escape(scanned_at)} &middot; "
        f"{escape(CIS_VERSION)}</div>"
        f"{body}</main></body></html>"
    )
    # Resource names and ARNs can contain the account number: hide it everywhere.
    page = page.replace(ctx.account_id, mask_account(ctx.account_id))
    # Plain ASCII (anything else becomes &#233; and so on), so no text encoding can garble it.
    return page.encode("ascii", "xmlcharrefreplace").decode("ascii")


def write_report(ctx: Context, results: list[Evidence], run_dir: Path) -> Path:
    path = run_dir / "report.html"
    path.write_text(render_report(ctx, results), encoding="utf-8")
    return path
