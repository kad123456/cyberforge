from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from html import escape
import json


def _text(value, fallback: str = "Not recorded") -> str:
    if value is None or value == "":
        return fallback
    return escape(str(value))


def _time(value) -> str:
    if isinstance(value, datetime):
        return escape(value.isoformat(sep=" ", timespec="seconds"))
    return _text(value)


def _detection_groups(detections, detection_summary):
    if detection_summary is not None:
        return detection_summary
    counts = Counter(
        (
            item.rule_id,
            item.rule_name,
            item.severity,
            item.technique_id,
            item.technique_name,
            item.tactic,
        )
        for item in detections
    )
    return [
        {
            "rule_id": key[0],
            "rule_name": key[1],
            "severity": key[2],
            "technique_id": key[3],
            "technique_name": key[4],
            "tactic": key[5],
            "count": count,
        }
        for key, count in counts.most_common()
    ]


def _table_rows(rows, columns, empty_message: str) -> str:
    if not rows:
        return f'<tr><td colspan="{len(columns)}" class="empty">{escape(empty_message)}</td></tr>'
    rendered = []
    for row in rows:
        cells = "".join(f"<td>{_text(value)}</td>" for value in row)
        rendered.append(f"<tr>{cells}</tr>")
    return "".join(rendered)


def report(incident, events, detections, reachability, detection_summary=None):
    """Build both the machine-readable evidence response and a printable report."""
    payload = {
        "incident": incident.model_dump(mode="json"),
        "timeline": [event.model_dump(mode="json", exclude={"raw_event"}) for event in events],
        "detections": [detection.model_dump() for detection in detections],
        "potential_reachability": reachability,
        "counts": {
            "linked_evidence_records": incident.event_count,
            "rule_detections": incident.detection_count,
            "timeline_records_included": len(events),
            "detection_rows_included": len(detections),
            "reachability_leads": len(reachability),
        },
        "recommended_steps": [
            "Validate the cited event IDs against the original telemetry before acting.",
            "Review authentication and network activity across the stated observation window.",
            "Confirm the listed accounts and systems with the identity and asset owners.",
            "Use existing SIEM/EDR procedures for containment decisions; this report does not confirm compromise.",
        ],
    }

    groups = _detection_groups(detections, detection_summary)
    technique_counts = Counter()
    tactic_by_technique = {}
    for group in groups:
        technique_id = group.get("technique_id")
        if technique_id:
            technique_counts[(technique_id, group.get("technique_name") or "Unknown")] += group.get("count", 0)
            tactic_by_technique.setdefault(technique_id, set()).add(group.get("tactic") or "Unknown")

    finding_rows = [
        (
            group.get("rule_name") or group.get("rule_id") or "Unspecified rule",
            (group.get("severity") or "informational").upper(),
            f"{group.get('count', 0):,}",
            f"{group.get('technique_id') or 'Unmapped'} · {group.get('technique_name') or 'No technique mapping'}",
            group.get("tactic") or "Unmapped",
        )
        for group in groups[:12]
    ]
    technique_rows = [
        (
            f"{technique_id} · {name}",
            ", ".join(sorted(tactic_by_technique[technique_id])),
            f"{count:,}",
        )
        for (technique_id, name), count in technique_counts.most_common(10)
    ]

    timeline_rows = []
    for event in events[:12]:
        endpoints = " → ".join(value for value in (event.source_ip, event.destination_ip) if value)
        timeline_rows.append((
            _time(event.timestamp),
            f"{event.category}: {event.action}",
            event.host,
            event.user,
            endpoints,
            event.event_id,
        ))

    lead_rows = []
    for lead in reachability[:8]:
        lead_rows.append((
            lead.get("potential_entity"),
            lead.get("relationship"),
            f"OBSERVED · {lead.get('confidence', 0):.0%}",
            lead.get("reason"),
            ", ".join(lead.get("supporting_event_ids", [])[:3]),
        ))

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    host_examples = incident.hosts[:6]
    user_examples = incident.users[:8]
    extra_groups = max(0, len(groups) - len(finding_rows))
    extra_techniques = max(0, len(technique_counts) - len(technique_rows))
    extra_events = max(0, incident.event_count - len(timeline_rows))
    risk_class = (incident.risk_label or "low").lower()

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Investigation report · {_text(incident.incident_id)}</title>
<style>
:root{{--navy:#0b1725;--ink:#1d2d3b;--muted:#607481;--teal:#087f70;--line:#dce5e8;--paper:#fff;--wash:#f1f5f6}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--wash);color:var(--ink);font:14px/1.55 Arial,Helvetica,sans-serif}}
.sheet{{max-width:1100px;margin:28px auto;background:var(--paper);padding:38px 46px;box-shadow:0 8px 32px #13263518}}
.top{{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:3px solid var(--teal);padding-bottom:18px}}
.brand{{font-size:13px;font-weight:700;letter-spacing:1.3px;color:var(--teal);text-transform:uppercase}}
h1{{font-size:30px;line-height:1.2;margin:8px 0 5px;color:var(--navy)}}.subtitle,.muted{{color:var(--muted)}}
.generated{{font-size:12px;color:var(--muted);text-align:right}}
.screen-actions{{display:flex;justify-content:flex-end;gap:10px;margin:14px 0}}
button{{background:var(--navy);color:white;border:0;border-radius:5px;padding:10px 15px;font-weight:600;cursor:pointer}}
h2{{font-size:18px;margin:30px 0 11px;color:var(--navy)}}h3{{font-size:14px;margin:0 0 8px;color:var(--navy)}}
.summary{{background:#edf7f5;border-left:4px solid var(--teal);padding:15px 18px;margin:20px 0}}
.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:16px 0}}
.metric{{border:1px solid var(--line);padding:13px 15px;border-radius:6px}}.metric span{{display:block;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}}.metric strong{{display:block;margin-top:4px;font-size:20px;color:var(--navy)}}
.risk{{font-weight:700}}.risk.high,.risk.critical{{color:#a42d24}}.risk.medium{{color:#8a5a00}}.risk.low{{color:#087f70}}
.facts{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}.fact{{border:1px solid var(--line);padding:15px;border-radius:6px}}
.fact p{{margin:5px 0}}.examples{{color:var(--muted);font-size:12px;overflow-wrap:anywhere}}
table{{width:100%;border-collapse:collapse;margin-top:8px;font-size:12px}}th{{background:var(--navy);color:#fff;text-align:left;font-weight:600}}th,td{{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}}tbody tr:nth-child(even){{background:#f7f9fa}}td:last-child{{overflow-wrap:anywhere}}.empty{{color:var(--muted);text-align:center;padding:18px}}
.notice{{padding:12px 15px;background:#fff8e7;border:1px solid #eddbac;border-radius:5px;color:#59481d}}
.recommendations li{{margin:7px 0}}footer{{border-top:1px solid var(--line);margin-top:32px;padding-top:14px;color:var(--muted);font-size:11px}}
@media(max-width:760px){{.sheet{{margin:0;padding:24px 18px}}.metrics{{grid-template-columns:repeat(2,1fr)}}.facts{{grid-template-columns:1fr}}.top{{display:block}}.generated{{text-align:left;margin-top:10px}}}}
@page{{size:A4;margin:14mm}}@media print{{body{{background:white;font-size:10pt}}.sheet{{max-width:none;margin:0;padding:0;box-shadow:none}}.screen-actions{{display:none}}h2{{break-after:avoid}}table{{break-inside:auto}}tr{{break-inside:avoid}}}}
</style>
</head>
<body><main class="sheet">
<header class="top"><div><div class="brand">ChainSight AI · Evidence-led investigation</div><h1>Incident investigation report</h1><div class="subtitle">A readable summary of linked detections and their supporting records.</div></div><div class="generated">Report generated<br><strong>{generated_at}</strong></div></header>
<div class="screen-actions"><button onclick="window.print()">Print / Save as PDF</button></div>
<section class="summary"><h3>Summary</h3><div>Incident <strong>{_text(incident.incident_id)}</strong> links <strong>{incident.detection_count:,} rule detections</strong> to <strong>{incident.event_count:,} evidence records</strong> across {len(incident.hosts):,} host(s), from {_time(incident.first_observed)} to {_time(incident.last_observed)}. The highest detection severity is <strong>{_text(incident.severity).upper()}</strong>. The risk score is a prioritization score; it does not by itself confirm malicious activity or compromise.</div></section>
<section><h2>Assessment</h2><div class="metrics">
<div class="metric"><span>Risk rating</span><strong class="risk {escape(risk_class)}">{_text(incident.risk_label)} · {incident.risk_score}/100</strong></div>
<div class="metric"><span>Highest severity</span><strong>{_text(incident.severity).upper()}</strong></div>
<div class="metric"><span>Rule confidence</span><strong>{incident.confidence:.0%}</strong><span>Mean rule confidence; not probability of compromise</span></div>
<div class="metric"><span>Evidence records</span><strong>{incident.event_count:,}</strong></div>
</div><div class="facts">
<div class="fact"><h3>Observation window</h3><p><strong>First:</strong> {_time(incident.first_observed)}</p><p><strong>Last:</strong> {_time(incident.last_observed)}</p></div>
<div class="fact"><h3>Entities recorded</h3><p><strong>Hosts:</strong> {len(incident.hosts):,}</p><p><strong>Accounts:</strong> {len(incident.users):,}</p><p class="examples">Host examples: {_text(', '.join(host_examples))}</p><p class="examples">Account examples: {_text(', '.join(user_examples))}{f' · plus {len(incident.users) - len(user_examples):,} more' if len(incident.users) > len(user_examples) else ''}</p></div>
</div></section>
<section><h2>What the rules detected</h2><p class="muted">Counts below cover all detections linked to this incident. They are rule matches supported by recorded evidence, not a confirmed attribution.</p>
<table><thead><tr><th>Finding</th><th>Severity</th><th>Detections</th><th>ATT&amp;CK technique</th><th>Tactic</th></tr></thead><tbody>{_table_rows(finding_rows, 5, 'No rule detections are available for this incident.')}</tbody></table>
{f'<p class="muted">Showing the 12 most frequent finding groups; {extra_groups} additional group(s) are included in the structured data.</p>' if extra_groups else ''}</section>
<section><h2>MITRE ATT&amp;CK techniques</h2><table><thead><tr><th>Technique</th><th>Tactic(s)</th><th>Detection count</th></tr></thead><tbody>{_table_rows(technique_rows, 3, 'No ATT&CK technique mapping was recorded.')}</tbody></table>
{f'<p class="muted">Showing the 10 most frequent techniques; {extra_techniques} additional technique(s) are included in the structured data.</p>' if extra_techniques else ''}</section>
<section><h2>Earliest linked evidence</h2><p class="muted">These are the earliest records returned for this incident, not a complete event listing. Each record ID can be searched in the original telemetry.</p>
<table><thead><tr><th>Time</th><th>Observed event</th><th>Host</th><th>Account</th><th>Network endpoints</th><th>Evidence record ID</th></tr></thead><tbody>{_table_rows(timeline_rows, 6, 'No event records are available.')}</tbody></table>
{f'<p class="muted">Showing {len(timeline_rows)} earliest records. The incident summary count covers {incident.event_count:,} linked records; {extra_events:,} are not displayed in this sample table.</p>' if extra_events else ''}</section>
<section><h2>Reachability leads</h2><div class="notice"><strong>Reachability is not compromise.</strong> These observed links are investigation leads only. A reachable or contacted entity is not labeled compromised by this report.</div>
<table><thead><tr><th>Entity</th><th>Observed relationship</th><th>Evidence status / confidence</th><th>Reason</th><th>Supporting record IDs</th></tr></thead><tbody>{_table_rows(lead_rows, 5, 'No reachability leads were returned.')}</tbody></table>
{f'<p class="muted">Showing {len(lead_rows)} of {len(reachability):,} returned reachability leads.</p>' if len(reachability) > len(lead_rows) else ''}</section>
<section><h2>Recommended review steps</h2><ol class="recommendations">{''.join(f'<li>{escape(step)}</li>' for step in payload['recommended_steps'])}</ol></section>
<footer>ChainSight AI is an offline investigation aid that complements SIEM and EDR systems. Review cited source evidence and organizational context before making response decisions. Risk and confidence values are prioritization aids, not proof of compromise.</footer>
</main></body></html>"""
    return payload, html
