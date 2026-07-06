from __future__ import annotations

from html import escape
from pathlib import Path


SEVERITY_COLORS = {
    "critical": "#b42318",
    "high": "#b54708",
    "medium": "#175cd3",
    "low": "#067647",
}


def write_dashboard(report, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_dashboard(report), encoding="utf-8")


def render_dashboard(report) -> str:
    report_dict = report.to_dict()
    incidents = report_dict["incidents"]
    campaigns = report_dict["campaigns"]
    memory = report_dict.get("memory") or {}
    import_diagnostics = report_dict.get("import_diagnostics") or {}
    max_score = max([incident["score"] for incident in incidents] or [0])
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI Cyberdefense Report</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #111827;
      --muted: #667085;
      --line: #d9dee7;
      --soft: #eef2f7;
      --accent: #155eef;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      letter-spacing: 0;
    }}
    header {{
      padding: 24px 32px 18px;
      background: #101828;
      color: #fff;
      border-bottom: 4px solid var(--accent);
    }}
    h1 {{
      margin: 0 0 12px;
      font-size: 28px;
      font-weight: 650;
    }}
    h2 {{
      margin: 0 0 14px;
      font-size: 18px;
      font-weight: 650;
    }}
    main {{
      max-width: 1280px;
      margin: 0 auto;
      padding: 22px 24px 42px;
    }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
    }}
    .metric, section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
    }}
    .metric {{
      padding: 14px 16px;
      min-height: 86px;
    }}
    .metric span {{
      display: block;
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      font-weight: 700;
    }}
    .metric strong {{
      display: block;
      margin-top: 8px;
      font-size: 28px;
    }}
    section {{
      margin-top: 18px;
      padding: 18px;
    }}
    .campaigns {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 12px;
    }}
    .campaign {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      background: #fbfcfe;
    }}
    .campaign-title {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: start;
      font-weight: 650;
    }}
    .table-wrap {{
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      min-width: 980px;
      background: #fff;
    }}
    th, td {{
      padding: 11px 12px;
      text-align: left;
      vertical-align: top;
      border-bottom: 1px solid var(--line);
      font-size: 14px;
    }}
    th {{
      background: var(--soft);
      color: #344054;
      font-size: 12px;
      text-transform: uppercase;
      font-weight: 750;
    }}
    tr:last-child td {{ border-bottom: 0; }}
    .badge {{
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      padding: 3px 8px;
      border-radius: 999px;
      color: #fff;
      font-weight: 700;
      font-size: 12px;
      white-space: nowrap;
    }}
    .scorebar {{
      height: 8px;
      width: 120px;
      background: #e4e7ec;
      border-radius: 999px;
      overflow: hidden;
      margin-top: 6px;
    }}
    .scorebar span {{
      display: block;
      height: 100%;
      background: var(--accent);
    }}
    .muted {{ color: var(--muted); }}
    .actions {{
      margin: 6px 0 0;
      padding-left: 18px;
    }}
    .actions li {{ margin: 3px 0; }}
    .feedback {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 10px;
    }}
    .feedback-item {{
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfcfe;
      font-size: 14px;
    }}
    .controls {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      margin-bottom: 12px;
    }}
    .controls input, .controls select {{
      min-height: 36px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 7px 10px;
      font: inherit;
      background: #fff;
    }}
    .controls input {{ min-width: min(320px, 100%); }}
    button {{
      min-height: 32px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 5px 9px;
      background: #fff;
      color: var(--text);
      font: inherit;
      cursor: pointer;
    }}
    button:hover {{ border-color: var(--accent); color: var(--accent); }}
    .details-row td {{
      background: #fbfcfe;
      color: #344054;
    }}
    pre {{
      margin: 0;
      white-space: pre-wrap;
      font-size: 12px;
      line-height: 1.45;
    }}
    .hidden {{ display: none; }}
    @media (max-width: 760px) {{
      header {{ padding: 20px; }}
      main {{ padding: 16px; }}
      .metrics {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      h1 {{ font-size: 24px; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>AI Cyberdefense Report</h1>
    <div class="muted">Defensive analysis, campaign correlation, response planning, and analyst memory.</div>
  </header>
  <main>
    <div class="metrics">
      <div class="metric"><span>Incidents</span><strong>{len(incidents)}</strong></div>
      <div class="metric"><span>Campaigns</span><strong>{len(campaigns)}</strong></div>
      <div class="metric"><span>Highest Score</span><strong>{max_score}</strong></div>
      <div class="metric"><span>Open Cases</span><strong>{escape(str(memory.get("open_cases", 0)))}</strong></div>
    </div>
    {render_import_diagnostics(import_diagnostics)}
    {render_campaigns(campaigns)}
    {render_entities(memory)}
    {render_feedback(memory)}
    {render_incidents(incidents)}
  </main>
  <script>
    const search = document.querySelector("[data-search]");
    const severity = document.querySelector("[data-severity]");
    const type = document.querySelector("[data-type]");
    const rows = Array.from(document.querySelectorAll("[data-incident-row]"));
    const count = document.querySelector("[data-visible-count]");

    function applyFilters() {{
      const query = (search?.value || "").toLowerCase();
      const selectedSeverity = severity?.value || "";
      const selectedType = type?.value || "";
      let visible = 0;
      rows.forEach((row) => {{
        const matchesQuery = !query || row.dataset.search.includes(query);
        const matchesSeverity = !selectedSeverity || row.dataset.severity === selectedSeverity;
        const matchesType = !selectedType || row.dataset.type === selectedType;
        const show = matchesQuery && matchesSeverity && matchesType;
        row.classList.toggle("hidden", !show);
        const details = document.getElementById(row.dataset.detailsId);
        if (details && !show) details.classList.add("hidden");
        if (show) visible += 1;
      }});
      if (count) count.textContent = String(visible);
    }}

    document.querySelectorAll("[data-toggle-details]").forEach((button) => {{
      button.addEventListener("click", () => {{
        const details = document.getElementById(button.dataset.toggleDetails);
        if (details) details.classList.toggle("hidden");
      }});
    }});
    [search, severity, type].forEach((control) => control?.addEventListener("input", applyFilters));
    applyFilters();
  </script>
</body>
</html>"""


def render_campaigns(campaigns: list[dict]) -> str:
    if not campaigns:
        return "<section><h2>Campaigns</h2><p class=\"muted\">No correlated campaigns.</p></section>"
    cards = []
    for campaign in campaigns:
        cards.append(
            f"""<article class="campaign">
  <div class="campaign-title">
    <span>{escape(campaign["campaign_id"])}</span>
    {severity_badge(campaign["severity"])}
  </div>
  <p>{escape(campaign["summary"])}</p>
  <div class="muted">Score {campaign["score"]}/100, {escape(campaign["confidence"])} confidence</div>
  <div class="muted">Reasons: {escape(", ".join(campaign["relation_reasons"]))}</div>
  {render_campaign_story(campaign)}
</article>"""
        )
    return f"<section><h2>Campaigns</h2><div class=\"campaigns\">{''.join(cards)}</div></section>"


def render_import_diagnostics(import_diagnostics: dict) -> str:
    issues = import_diagnostics.get("issues") or []
    if not issues:
        return "<section><h2>Import Diagnostics</h2><p class=\"muted\">No malformed records skipped.</p></section>"
    items = []
    for issue in issues[:20]:
        raw = f"<div class=\"muted\">{escape(issue.get('raw') or '')}</div>" if issue.get("raw") else ""
        items.append(
            f"""<div class="feedback-item">
  <strong>Line {escape(str(issue.get("line_number")))}</strong>
  <div>{escape(issue.get("message") or "")}</div>
  {raw}
</div>"""
        )
    return f"<section><h2>Import Diagnostics</h2><div class=\"feedback\">{''.join(items)}</div></section>"


def render_feedback(memory: dict) -> str:
    matches = memory.get("feedback_matches") or []
    if not matches:
        return "<section><h2>Feedback Context</h2><p class=\"muted\">No prior analyst feedback matched this report.</p></section>"
    items = []
    for match in matches:
        note = f"<div>{escape(match.get('note') or '')}</div>" if match.get("note") else ""
        items.append(
            f"""<div class="feedback-item">
  <strong>{escape(match["attack_type"])}</strong>
  <div>Prior verdict: {escape(match["verdict"])}</div>
  <div>Incident ID: {escape(str(match["matched_incident_id"]))}</div>
  {note}
</div>"""
        )
    return f"<section><h2>Feedback Context</h2><div class=\"feedback\">{''.join(items)}</div></section>"


def render_entities(memory: dict) -> str:
    top_entities = memory.get("top_entities") or {}
    if not any(top_entities.values()):
        return "<section><h2>Entity Profiles</h2><p class=\"muted\">No entity memory available.</p></section>"
    items = []
    for entity_type, profiles in sorted(top_entities.items()):
        for profile in profiles[:5]:
            items.append(
                f"""<div class="feedback-item">
  <strong>{escape(entity_type)}: {escape(profile["value"])}</strong>
  <div>Incidents: {escape(str(profile["incident_count"]))}</div>
  <div>Cases: {escape(str(profile["case_count"]))}</div>
  <div class="muted">Last seen: {escape(profile["last_seen"])}</div>
</div>"""
            )
    return f"<section><h2>Entity Profiles</h2><div class=\"feedback\">{''.join(items)}</div></section>"


def render_incidents(incidents: list[dict]) -> str:
    type_options = "".join(
        f'<option value="{escape(attack_type)}">{escape(attack_type)}</option>'
        for attack_type in sorted({incident["attack_type"] for incident in incidents})
    )
    rows = []
    for index, incident in enumerate(incidents, start=1):
        actions = "".join(
            f"<li>{escape(step['action'])}</li>" for step in incident["response_plan"]
        )
        explanation = render_explanation(incident.get("explanation") or {})
        search_text = escape(
            " ".join(
                [
                    incident["attack_type"],
                    incident["summary"],
                    " ".join(incident["affected_assets"]),
                    " ".join(incident["source_ips"]),
                    incident.get("rule_name", ""),
                ]
            ).lower()
        )
        details_id = f"incident-details-{index}"
        evidence = escape(json_like(incident.get("evidence") or []))
        risk = render_risk_signals(incident.get("risk_signals") or [])
        investigation = render_investigation(incident.get("investigation") or {})
        rows.append(
            f"""<tr data-incident-row data-severity="{escape(incident["severity"])}" data-type="{escape(incident["attack_type"])}" data-search="{search_text}" data-details-id="{details_id}">
  <td>{severity_badge(incident["severity"])}<div class="scorebar"><span style="width:{incident["score"]}%"></span></div><div class="muted">{incident["score"]}/100</div></td>
  <td><strong>{escape(incident["attack_type"])}</strong><div class="muted">{escape(incident["technique_id"])} / {escape(incident["tactic"])}</div></td>
  <td>{escape(incident["summary"])}{investigation}{risk}</td>
  <td><strong>{escape(incident.get("rule_name", ""))}</strong>{explanation}</td>
  <td>{escape(", ".join(incident["affected_assets"]))}</td>
  <td>{escape(", ".join(incident["source_ips"]))}</td>
  <td>{escape(incident["timeline"]["first_seen"])}<br><span class="muted">{escape(incident["timeline"]["last_seen"])}</span></td>
  <td><button type="button" data-toggle-details="{details_id}">Evidence</button><ul class="actions">{actions}</ul></td>
</tr>
<tr id="{details_id}" class="details-row hidden">
  <td colspan="8"><pre>{evidence}</pre></td>
</tr>"""
        )
    return f"""<section>
  <h2>Incidents</h2>
  <div class="controls" aria-label="Incident filters">
    <input data-search type="search" placeholder="Search incidents">
    <select data-severity aria-label="Filter by severity">
      <option value="">All severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
    </select>
    <select data-type aria-label="Filter by type">
      <option value="">All types</option>
      {type_options}
    </select>
    <span class="muted"><span data-visible-count>{len(incidents)}</span> visible</span>
  </div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Type</th>
          <th>Summary</th>
          <th>Why</th>
          <th>Assets</th>
          <th>Sources</th>
          <th>Timeline</th>
          <th>Response Plan</th>
        </tr>
      </thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>
</section>"""


def render_explanation(explanation: dict) -> str:
    if not explanation:
        return ""
    items = "".join(
        f"<li><span class=\"muted\">{escape(str(key))}</span>: {escape(str(value))}</li>"
        for key, value in explanation.items()
    )
    return f"<ul class=\"actions\">{items}</ul>"


def render_campaign_story(campaign: dict) -> str:
    steps = campaign.get("investigation_timeline") or []
    if not steps:
        return ""
    items = "".join(
        f"<li><span class=\"muted\">{escape(step['timestamp'])}</span>: "
        f"{escape(step['attack_type'])} on {escape(', '.join(step['assets']))}</li>"
        for step in steps
    )
    assessment = campaign.get("analyst_assessment") or {}
    next_question = assessment.get("next_question")
    question = (
        f"<div class=\"muted\">Next question: {escape(next_question)}</div>"
        if next_question
        else ""
    )
    return f"<ul class=\"actions\">{items}</ul>{question}"


def render_risk_signals(signals: list[dict]) -> str:
    if not signals:
        return ""
    items = "".join(
        f"<li><span class=\"muted\">{escape(signal['signal'])}</span>: "
        f"{escape(signal['detail'])}</li>"
        for signal in signals
    )
    return f"<div class=\"muted\">Risk signals</div><ul class=\"actions\">{items}</ul>"


def render_investigation(investigation: dict) -> str:
    if not investigation:
        return ""
    readiness = investigation.get("response_readiness") or {}
    confidence = investigation.get("confidence_assessment") or {}
    lines = [
        f"<li>{escape(investigation.get('why_it_matters') or '')}</li>",
        (
            f"<li><span class=\"muted\">Confidence</span>: "
            f"{escape(confidence.get('adjusted_confidence') or 'unknown')}</li>"
        ),
        (
            f"<li><span class=\"muted\">Readiness</span>: "
            f"{escape(readiness.get('overall_state') or 'unknown')}</li>"
        ),
    ]
    return f"<div class=\"muted\">Investigation</div><ul class=\"actions\">{''.join(lines)}</ul>"


def severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#344054")
    return (
        f'<span class="badge" style="background:{color}">'
        f"{escape(severity.upper())}</span>"
    )


def json_like(value: object) -> str:
    import json

    return json.dumps(value, indent=2)
