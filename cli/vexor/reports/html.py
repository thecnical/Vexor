"""
Vexor HTML Report Generator v2.0.0 — Professional Dark Theme
Executive summary · Risk gauge · Severity charts · CVSS scores · PoC
"""
import datetime
from pathlib import Path
from collections import Counter
from jinja2 import Template
from vexor.config import TOOL_VERSION, TOOL_AUTHOR


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ title }}</title>
<style>
  /* ── Reset & Base ── */
  *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
  :root {
    --bg: #0a0a0f;
    --bg2: #0d0d1a;
    --bg3: #111122;
    --border: #1a1a2e;
    --cyan: #00ffff;
    --magenta: #ff00ff;
    --green: #00ff88;
    --yellow: #ffaa00;
    --red: #ff4444;
    --critical: #ff0000;
    --high: #ff4400;
    --medium: #ffaa00;
    --low: #00aaff;
    --info: #888888;
    --text: #cccccc;
    --dim: #666666;
  }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Courier New', 'Consolas', monospace;
    font-size: 14px;
    line-height: 1.6;
  }
  a { color: var(--cyan); text-decoration: none; }
  a:hover { text-decoration: underline; }
  code, pre {
    background: #050508;
    border: 1px solid var(--border);
    border-radius: 3px;
    font-family: 'Courier New', monospace;
    font-size: 12px;
  }
  code { padding: 1px 5px; }
  pre { padding: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }

  /* ── Layout ── */
  .header {
    background: var(--bg2);
    border-bottom: 2px solid var(--cyan);
    padding: 30px 40px;
    position: relative;
  }
  .header-top { display: flex; justify-content: space-between; align-items: flex-start; }
  .logo { color: var(--cyan); font-size: 28px; font-weight: bold; letter-spacing: 2px; }
  .logo span { color: var(--magenta); }
  .version-badge {
    background: var(--magenta);
    color: #000;
    padding: 3px 10px;
    border-radius: 3px;
    font-size: 12px;
    font-weight: bold;
  }
  .subtitle { color: var(--magenta); margin-top: 6px; font-size: 13px; }
  .meta { color: var(--dim); margin-top: 8px; font-size: 12px; }
  .meta span { color: var(--text); }

  .container { max-width: 1300px; margin: 0 auto; padding: 30px 40px; }

  /* ── Section titles ── */
  .section-title {
    color: var(--magenta);
    font-size: 16px;
    font-weight: bold;
    margin: 35px 0 15px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
    letter-spacing: 1px;
  }
  .section-title::before { content: "◈ "; color: var(--cyan); }

  /* ── Executive Summary ── */
  .exec-summary {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 20px;
    margin-bottom: 20px;
  }
  .exec-text { color: var(--text); line-height: 1.8; margin-bottom: 15px; }

  /* ── Risk Gauge ── */
  .risk-gauge-container {
    display: flex;
    align-items: center;
    gap: 30px;
    margin: 20px 0;
    flex-wrap: wrap;
  }
  .gauge-wrap { text-align: center; }
  .gauge-label { color: var(--dim); font-size: 11px; margin-top: 5px; }
  .gauge-ascii {
    font-family: monospace;
    font-size: 13px;
    line-height: 1.3;
    white-space: pre;
  }

  /* ── Stat Cards ── */
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 15px;
    margin: 20px 0;
  }
  .stat-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    padding: 20px 15px;
    text-align: center;
    border-radius: 4px;
    transition: border-color 0.2s;
  }
  .stat-card:hover { border-color: var(--cyan); }
  .stat-value { font-size: 36px; font-weight: bold; line-height: 1; }
  .stat-label { color: var(--dim); font-size: 11px; margin-top: 6px; letter-spacing: 1px; }
  .c-critical { color: var(--critical); }
  .c-high { color: var(--high); }
  .c-medium { color: var(--medium); }
  .c-low { color: var(--low); }
  .c-info { color: var(--info); }
  .c-total { color: var(--text); }

  /* ── Severity Chart (ASCII) ── */
  .chart-container {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 20px;
    margin: 15px 0;
    font-family: monospace;
  }
  .chart-title { color: var(--cyan); margin-bottom: 12px; font-size: 13px; }
  .chart-bar { display: flex; align-items: center; margin: 4px 0; gap: 10px; }
  .chart-label { width: 80px; color: var(--dim); font-size: 12px; text-align: right; }
  .chart-fill { height: 18px; border-radius: 2px; min-width: 2px; }
  .chart-count { color: var(--text); font-size: 12px; min-width: 30px; }
  .fill-critical { background: var(--critical); }
  .fill-high { background: var(--high); }
  .fill-medium { background: var(--medium); }
  .fill-low { background: var(--low); }
  .fill-info { background: var(--info); }

  /* ── Scan Metadata ── */
  .scan-meta {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 10px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 15px;
    margin: 15px 0;
  }
  .meta-item { display: flex; flex-direction: column; gap: 3px; }
  .meta-key { color: var(--dim); font-size: 11px; letter-spacing: 1px; }
  .meta-val { color: var(--cyan); font-size: 13px; }

  /* ── Findings Table ── */
  .findings-table-wrap { overflow-x: auto; margin: 15px 0; }
  table { width: 100%; border-collapse: collapse; }
  th {
    background: var(--bg3);
    color: var(--cyan);
    padding: 10px 12px;
    text-align: left;
    font-size: 12px;
    letter-spacing: 1px;
    border-bottom: 1px solid var(--border);
  }
  td {
    padding: 9px 12px;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
    vertical-align: top;
  }
  tr:hover td { background: var(--bg2); }
  .sev-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 1px;
  }
  .sev-CRITICAL { background: #3a0000; color: var(--critical); border: 1px solid var(--critical); }
  .sev-HIGH { background: #2a1000; color: var(--high); border: 1px solid var(--high); }
  .sev-MEDIUM { background: #2a1a00; color: var(--medium); border: 1px solid var(--medium); }
  .sev-LOW { background: #001a2a; color: var(--low); border: 1px solid var(--low); }
  .sev-INFO { background: #1a1a1a; color: var(--info); border: 1px solid var(--info); }

  /* ── Finding Detail Cards ── */
  .finding-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 4px;
    margin: 20px 0;
    overflow: hidden;
  }
  .finding-card-header {
    padding: 12px 20px;
    display: flex;
    align-items: center;
    gap: 12px;
    border-bottom: 1px solid var(--border);
  }
  .finding-card-header.CRITICAL { border-left: 4px solid var(--critical); }
  .finding-card-header.HIGH { border-left: 4px solid var(--high); }
  .finding-card-header.MEDIUM { border-left: 4px solid var(--medium); }
  .finding-card-header.LOW { border-left: 4px solid var(--low); }
  .finding-card-header.INFO { border-left: 4px solid var(--info); }
  .finding-title { color: var(--text); font-size: 15px; font-weight: bold; }
  .finding-body { padding: 20px; }
  .finding-grid {
    display: grid;
    grid-template-columns: 140px 1fr;
    gap: 8px 15px;
    margin-bottom: 15px;
  }
  .fg-key { color: var(--dim); font-size: 12px; padding-top: 2px; }
  .fg-val { color: var(--text); font-size: 13px; word-break: break-all; }
  .cvss-score {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 3px;
    font-weight: bold;
    font-size: 14px;
  }
  .cvss-critical { background: #3a0000; color: var(--critical); }
  .cvss-high { background: #2a1000; color: var(--high); }
  .cvss-medium { background: #2a1a00; color: var(--medium); }
  .cvss-low { background: #001a2a; color: var(--low); }

  .section-sub { color: var(--cyan); font-size: 12px; margin: 12px 0 6px; letter-spacing: 1px; }
  .evidence-box {
    background: #050508;
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 10px;
    font-size: 12px;
    white-space: pre-wrap;
    word-break: break-all;
    color: var(--green);
    max-height: 200px;
    overflow-y: auto;
  }
  .poc-box {
    background: #050508;
    border: 1px solid var(--high);
    border-radius: 3px;
    padding: 10px;
    font-size: 12px;
    white-space: pre-wrap;
    word-break: break-all;
    color: var(--yellow);
    max-height: 200px;
    overflow-y: auto;
  }
  .remediation-box {
    background: #001a0a;
    border: 1px solid #004422;
    border-radius: 3px;
    padding: 10px;
    font-size: 13px;
    color: var(--green);
  }

  /* ── Severity Groups ── */
  .severity-group { margin: 25px 0; }
  .severity-group-header {
    padding: 8px 15px;
    border-radius: 3px;
    font-weight: bold;
    font-size: 13px;
    letter-spacing: 1px;
    margin-bottom: 10px;
  }
  .sg-CRITICAL { background: #1a0000; color: var(--critical); border: 1px solid var(--critical); }
  .sg-HIGH { background: #150800; color: var(--high); border: 1px solid var(--high); }
  .sg-MEDIUM { background: #150d00; color: var(--medium); border: 1px solid var(--medium); }
  .sg-LOW { background: #000d15; color: var(--low); border: 1px solid var(--low); }
  .sg-INFO { background: #0d0d0d; color: var(--info); border: 1px solid var(--info); }

  /* ── Footer ── */
  .footer {
    text-align: center;
    color: var(--dim);
    padding: 25px;
    border-top: 1px solid var(--border);
    margin-top: 50px;
    font-size: 12px;
  }
  .footer span { color: var(--cyan); }
</style>
</head>
<body>

<!-- ── Header ── -->
<div class="header">
  <div class="header-top">
    <div>
      <div class="logo">⬡ VEXOR<span> SECURITY REPORT</span></div>
      <div class="subtitle">AI-Powered CLI Security Toolkit</div>
    </div>
    <div class="version-badge">v{{ version }}</div>
  </div>
  <div class="meta">
    Target: <span>{{ target }}</span> &nbsp;|&nbsp;
    Date: <span>{{ date }}</span> &nbsp;|&nbsp;
    Duration: <span>{{ duration }}</span> &nbsp;|&nbsp;
    Modules: <span>{{ modules_used }}</span> &nbsp;|&nbsp;
    Author: <span>{{ author }}</span>
  </div>
</div>

<div class="container">

  <!-- ── Executive Summary ── -->
  <div class="section-title">EXECUTIVE SUMMARY</div>
  <div class="exec-summary">
    <div class="exec-text">{{ exec_summary }}</div>

    <!-- Risk Gauge (ASCII art) -->
    <div class="risk-gauge-container">
      <div class="gauge-wrap">
        <div class="gauge-ascii">{{ risk_gauge }}</div>
        <div class="gauge-label">OVERALL RISK: {{ risk_level }}</div>
      </div>
    </div>
  </div>

  <!-- ── Scan Metadata ── -->
  <div class="scan-meta">
    <div class="meta-item">
      <span class="meta-key">TARGET</span>
      <span class="meta-val">{{ target }}</span>
    </div>
    <div class="meta-item">
      <span class="meta-key">SCAN DATE</span>
      <span class="meta-val">{{ date }}</span>
    </div>
    <div class="meta-item">
      <span class="meta-key">DURATION</span>
      <span class="meta-val">{{ duration }}</span>
    </div>
    <div class="meta-item">
      <span class="meta-key">MODULES USED</span>
      <span class="meta-val">{{ modules_used }}</span>
    </div>
    <div class="meta-item">
      <span class="meta-key">TOTAL FINDINGS</span>
      <span class="meta-val">{{ total }}</span>
    </div>
    <div class="meta-item">
      <span class="meta-key">TOOL VERSION</span>
      <span class="meta-val">Vexor v{{ version }}</span>
    </div>
  </div>

  <!-- ── Stats ── -->
  <div class="summary-grid">
    <div class="stat-card">
      <div class="stat-value c-total">{{ total }}</div>
      <div class="stat-label">TOTAL</div>
    </div>
    <div class="stat-card">
      <div class="stat-value c-critical">{{ critical }}</div>
      <div class="stat-label">CRITICAL</div>
    </div>
    <div class="stat-card">
      <div class="stat-value c-high">{{ high }}</div>
      <div class="stat-label">HIGH</div>
    </div>
    <div class="stat-card">
      <div class="stat-value c-medium">{{ medium }}</div>
      <div class="stat-label">MEDIUM</div>
    </div>
    <div class="stat-card">
      <div class="stat-value c-low">{{ low }}</div>
      <div class="stat-label">LOW</div>
    </div>
    <div class="stat-card">
      <div class="stat-value c-info">{{ info_count }}</div>
      <div class="stat-label">INFO</div>
    </div>
  </div>

  <!-- ── Severity Distribution Chart ── -->
  <div class="chart-container">
    <div class="chart-title">▸ SEVERITY DISTRIBUTION</div>
    {% for sev, count, color_class, bar_width in severity_chart %}
    <div class="chart-bar">
      <div class="chart-label">{{ sev }}</div>
      <div class="chart-fill fill-{{ sev|lower }}" style="width: {{ bar_width }}px;"></div>
      <div class="chart-count">{{ count }}</div>
    </div>
    {% endfor %}
  </div>

  <!-- ── Findings by Severity ── -->
  <div class="section-title">FINDINGS BY SEVERITY</div>

  {% for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] %}
  {% set sev_findings = findings | selectattr('severity', 'equalto', sev) | list %}
  {% if sev_findings %}
  <div class="severity-group">
    <div class="severity-group-header sg-{{ sev }}">
      {{ sev }} — {{ sev_findings | length }} finding(s)
    </div>
    <div class="findings-table-wrap">
      <table>
        <tr>
          <th>SEVERITY</th>
          <th>MODULE</th>
          <th>VULNERABILITY</th>
          <th>ENDPOINT</th>
          <th>PARAMETER</th>
          <th>CVSS</th>
        </tr>
        {% for f in sev_findings %}
        <tr>
          <td><span class="sev-badge sev-{{ f.severity }}">{{ f.severity }}</span></td>
          <td>{{ f.module }}</td>
          <td>{{ f.vuln }}</td>
          <td style="word-break:break-all;max-width:250px">{{ f.endpoint }}</td>
          <td>{{ f.param or '—' }}</td>
          <td>
            {% if f.cvss_score %}
            <span class="cvss-score cvss-{{ f.severity|lower }}">{{ f.cvss_score }}</span>
            {% else %}—{% endif %}
          </td>
        </tr>
        {% endfor %}
      </table>
    </div>
  </div>
  {% endif %}
  {% endfor %}

  {% if not findings %}
  <div style="text-align:center;color:var(--green);padding:30px">
    ✓ No vulnerabilities found
  </div>
  {% endif %}

  <!-- ── Detailed Findings ── -->
  {% if findings %}
  <div class="section-title">DETAILED FINDINGS</div>

  {% for f in findings %}
  <div class="finding-card">
    <div class="finding-card-header {{ f.severity }}">
      <span class="sev-badge sev-{{ f.severity }}">{{ f.severity }}</span>
      <span class="finding-title">{{ f.vuln }}</span>
      {% if f.cvss_score %}
      <span class="cvss-score cvss-{{ f.severity|lower }}" style="margin-left:auto">
        CVSS {{ f.cvss_score }}
      </span>
      {% endif %}
    </div>
    <div class="finding-body">
      <div class="finding-grid">
        <div class="fg-key">Module</div>
        <div class="fg-val">{{ f.module }}</div>
        <div class="fg-key">Endpoint</div>
        <div class="fg-val">{{ f.endpoint }}</div>
        {% if f.param %}
        <div class="fg-key">Parameter</div>
        <div class="fg-val"><code>{{ f.param }}</code></div>
        {% endif %}
        {% if f.payload %}
        <div class="fg-key">Payload</div>
        <div class="fg-val"><code>{{ f.payload }}</code></div>
        {% endif %}
      </div>

      <div class="section-sub">▸ DESCRIPTION</div>
      <p style="color:var(--text);margin-bottom:12px">{{ f.description }}</p>

      {% if f.evidence %}
      <div class="section-sub">▸ EVIDENCE</div>
      <div class="evidence-box">{{ f.evidence }}</div>
      {% endif %}

      {% if f.poc %}
      <div class="section-sub">▸ PROOF OF CONCEPT</div>
      <div class="poc-box">{{ f.poc }}</div>
      {% endif %}

      <div class="section-sub">▸ REMEDIATION</div>
      <div class="remediation-box">{{ f.remediation or 'Review and fix the identified vulnerability.' }}</div>

      {% if f.ai_note %}
      <div class="section-sub">▸ AI ANALYSIS</div>
      <p style="color:var(--cyan);font-size:13px;margin-top:6px">{{ f.ai_note }}</p>
      {% endif %}
    </div>
  </div>
  {% endfor %}
  {% endif %}

</div>

<div class="footer">
  Generated by <span>Vexor v{{ version }}</span> &nbsp;|&nbsp;
  Created by <span>{{ author }}</span> &nbsp;|&nbsp;
  <span>{{ date }}</span>
</div>

</body>
</html>"""


def _build_risk_gauge(score: float) -> tuple[str, str]:
    """Build ASCII risk gauge and level label"""
    if score == 0:
        level = "NONE"
        filled = 0
    elif score < 3:
        level = "LOW"
        filled = 2
    elif score < 6:
        level = "MEDIUM"
        filled = 4
    elif score < 8:
        level = "HIGH"
        filled = 7
    elif score < 9.5:
        level = "HIGH"
        filled = 8
    else:
        level = "CRITICAL"
        filled = 10

    bar = "█" * filled + "░" * (10 - filled)
    colors = {
        "NONE": "[ " + bar + " ]",
        "LOW": "[ " + bar + " ]",
        "MEDIUM": "[ " + bar + " ]",
        "HIGH": "[ " + bar + " ]",
        "CRITICAL": "[ " + bar + " ]",
    }
    gauge = (
        f"  ┌──────────────┐\n"
        f"  │ {bar} │\n"
        f"  └──────────────┘\n"
        f"  0    5    10\n"
        f"  Score: {score:.1f}/10"
    )
    return gauge, level


def _build_severity_chart(counts: dict, total: int) -> list:
    """Build data for severity distribution bar chart"""
    max_bar = 300
    chart = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = counts.get(sev, 0)
        width = int((count / total) * max_bar) if total > 0 else 0
        chart.append((sev, count, f"fill-{sev.lower()}", max(width, 2 if count > 0 else 0)))
    return chart


def _build_exec_summary(findings: list, target: str, counts: dict, total: int) -> str:
    """Build executive summary text"""
    if total == 0:
        return (
            f"Security assessment of {target} completed with no vulnerabilities identified. "
            "The target appears to be well-secured against the tested attack vectors."
        )

    critical = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    medium = counts.get("MEDIUM", 0)

    risk_desc = "low"
    if critical > 0:
        risk_desc = "critical"
    elif high > 0:
        risk_desc = "high"
    elif medium > 0:
        risk_desc = "medium"

    modules = list({f.get("module", "unknown") for f in findings})

    summary = (
        f"Security assessment of {target} identified {total} finding(s) "
        f"with an overall {risk_desc.upper()} risk rating. "
    )
    if critical > 0:
        summary += (
            f"{critical} CRITICAL vulnerability(ies) require immediate remediation. "
        )
    if high > 0:
        summary += f"{high} HIGH severity issue(s) were identified. "
    if medium > 0:
        summary += f"{medium} MEDIUM severity issue(s) require attention. "

    summary += (
        f"Assessment covered {len(modules)} module(s): "
        f"{', '.join(sorted(modules)[:5])}."
    )
    return summary


class HTMLReport:
    def __init__(self, title: str = "Vexor Security Report"):
        self.title = title

    async def generate(
        self,
        output_path: str,
        findings: list = None,
        target: str = "",
        duration: str = "N/A",
        modules_used: str = "N/A",
        scan_start: str = "",
    ) -> str:
        findings = findings or []
        counts = Counter(f.get("severity", "INFO") for f in findings)
        total = len(findings)

        # Risk score: weighted average
        weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 0.5}
        if total > 0:
            raw_score = sum(
                weights.get(f.get("severity", "INFO"), 1) for f in findings
            )
            risk_score = min(10.0, raw_score / max(total, 1) * 1.5)
        else:
            risk_score = 0.0

        risk_gauge, risk_level = _build_risk_gauge(risk_score)
        severity_chart = _build_severity_chart(counts, total)
        exec_summary = _build_exec_summary(findings, target or "N/A", counts, total)

        # Ensure all findings have required fields
        normalized = []
        for f in findings:
            nf = dict(f)
            nf.setdefault("severity", "INFO")
            nf.setdefault("module", "unknown")
            nf.setdefault("vuln", "Unknown")
            nf.setdefault("endpoint", target or "N/A")
            nf.setdefault("param", "")
            nf.setdefault("payload", "")
            nf.setdefault("evidence", "")
            nf.setdefault("poc", "")
            nf.setdefault("description", "")
            nf.setdefault("remediation", "")
            nf.setdefault("ai_note", "")
            nf.setdefault("cvss_score", "")
            normalized.append(nf)

        # Sort: CRITICAL first
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        normalized.sort(key=lambda x: sev_order.get(x["severity"], 5))

        template = Template(HTML_TEMPLATE)
        html = template.render(
            title=self.title,
            version=TOOL_VERSION,
            author=TOOL_AUTHOR,
            target=target or "N/A",
            date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            duration=duration,
            modules_used=modules_used,
            findings=normalized,
            total=total,
            critical=counts.get("CRITICAL", 0),
            high=counts.get("HIGH", 0),
            medium=counts.get("MEDIUM", 0),
            low=counts.get("LOW", 0),
            info_count=counts.get("INFO", 0),
            risk_gauge=risk_gauge,
            risk_level=risk_level,
            risk_score=f"{risk_score:.1f}",
            exec_summary=exec_summary,
            severity_chart=severity_chart,
        )

        Path(output_path).write_text(html, encoding="utf-8")
        return output_path
