"""Rapport HTML (lisible par un humain), autonome et coloré par sévérité.

Rendu via jinja2. Le HTML est autonome (CSS en ligne), ouvrable dans un
navigateur ou imprimable en PDF pour le rapport final.
"""

from __future__ import annotations

from datetime import datetime

from jinja2 import Template

from pipeline import __version__
from pipeline.models import Report

# Sévérité -> (couleur texte, couleur fond, libellé).
_SEV_STYLE = {
    "critical": ("#b3261e", "#fce8e6", "CRITICAL"),
    "high": ("#c8641d", "#fdefe3", "HIGH"),
    "medium": ("#8a6d1a", "#fbf3d9", "MEDIUM"),
    "low": ("#1a5fb4", "#e7f0fb", "LOW"),
    "info": ("#5c5c5c", "#ededed", "INFO"),
}

_TEMPLATE = Template("""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport argus : {{ target }}</title>
<style>
  :root { --bord: #e2e2e6; --fg: #1b1b1f; --muted: #5c5c66; --bg: #ffffff; --panel: #f7f7f9; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         color: var(--fg); background: var(--bg); line-height: 1.5; }
  .wrap { max-width: 980px; margin: 0 auto; padding: 28px 20px 60px; }
  header h1 { margin: 0 0 4px; font-size: 22px; }
  header .sub { color: var(--muted); font-size: 13px; word-break: break-all; }
  h2 { font-size: 15px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted);
       border-bottom: 1px solid var(--bord); padding-bottom: 6px; margin: 30px 0 14px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  @media (max-width: 640px) { .grid { grid-template-columns: 1fr; } }
  .panel { background: var(--panel); border: 1px solid var(--bord); border-radius: 10px; padding: 14px 16px; }
  .kv { display: flex; justify-content: space-between; gap: 12px; padding: 3px 0; font-size: 14px; }
  .kv .k { color: var(--muted); }
  .badge { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 12px;
           font-weight: 600; margin: 3px 6px 3px 0; }
  .on { background: #e6f4ea; color: #146c2e; } .off { background: #fce8e6; color: #b3261e; }
  .tiles { display: flex; flex-wrap: wrap; gap: 10px; }
  .tile { border: 1px solid var(--bord); border-radius: 10px; padding: 10px 14px; min-width: 92px; }
  .tile .n { font-size: 22px; font-weight: 700; } .tile .l { font-size: 12px; color: var(--muted); }
  .finding { border: 1px solid var(--bord); border-left-width: 5px; border-radius: 10px;
             padding: 14px 16px; margin: 12px 0; }
  .finding h3 { margin: 0 0 8px; font-size: 16px; }
  .sev { display: inline-block; padding: 2px 9px; border-radius: 6px; font-weight: 700;
         font-size: 12px; margin-right: 8px; vertical-align: middle; }
  .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 4px 16px;
          font-size: 13px; margin: 8px 0; }
  .meta .k { color: var(--muted); }
  .desc { margin: 8px 0; }
  .rem { background: #f0f6ff; border-radius: 8px; padding: 8px 12px; font-size: 14px; }
  .ev { font-family: ui-monospace, monospace; font-size: 12px; color: var(--muted); margin-top: 8px;
        word-break: break-all; }
  code { font-family: ui-monospace, monospace; }
  footer { margin-top: 40px; color: var(--muted); font-size: 12px; text-align: center; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Rapport d'analyse de vulnérabilités</h1>
    <div class="sub">Cible : <code>{{ target }}</code></div>
    <div class="sub">Généré le {{ generated }} par argus {{ version }}</div>
  </header>

  {% if elf %}
  <h2>Cible</h2>
  <div class="grid">
    <div class="panel">
      <div class="kv"><span class="k">Architecture</span><span>{{ elf.arch }} ({{ elf.bits }} bits)</span></div>
      <div class="kv"><span class="k">Type</span><span>{{ "PIE" if elf.is_pie else "exécutable non-PIE" }}</span></div>
      <div class="kv"><span class="k">Point d'entrée</span><span><code>0x{{ '%x' % elf.entrypoint }}</code></span></div>
      <div class="kv"><span class="k">Symboles</span><span>{{ "présents" if elf.has_symbols else "absents" }}</span></div>
      <div class="kv"><span class="k">Fonctions</span><span>{{ elf.functions|length }} déf. / {{ elf.imports|length }} imp.</span></div>
    </div>
    <div class="panel">
      <div style="margin-bottom:6px; color:var(--muted); font-size:13px;">Protections</div>
      {% for name, active, detail in protections %}
        <span class="badge {{ 'on' if active else 'off' }}">{{ name }}{% if detail %} : {{ detail }}{% endif %}</span>
      {% endfor %}
    </div>
  </div>
  {% endif %}

  <h2>Synthèse</h2>
  <div class="tiles">
    <div class="tile"><div class="n">{{ findings|length }}</div><div class="l">finding(s)</div></div>
    {% for sev, count in severites %}
      <div class="tile" style="border-color:{{ sev.color }}">
        <div class="n" style="color:{{ sev.color }}">{{ count }}</div><div class="l">{{ sev.label }}</div>
      </div>
    {% endfor %}
  </div>

  <h2>Vulnérabilités</h2>
  {% if not findings %}<p>Aucune vulnérabilité détectée.</p>{% endif %}
  {% for f in findings %}
  <div class="finding" style="border-left-color:{{ f.color }}; background:{{ f.bg }}22;">
    <h3><span class="sev" style="background:{{ f.bg }}; color:{{ f.color }}">{{ f.label }} {{ f.score }}</span>
        {{ f.vuln_class }} — <code>{{ f.function }}</code></h3>
    <div class="meta">
      <div><span class="k">Confiance :</span> {{ f.confidence }}</div>
      <div><span class="k">Exploitabilité :</span> {{ f.exploitability }}</div>
      <div><span class="k">Offset statique :</span> <code>{{ f.static_offset }}</code></div>
      <div><span class="k">Offset exploit :</span> <code>{{ f.exploit_offset }}</code></div>
      <div style="grid-column:1/-1;"><span class="k">Sources :</span> {{ f.sources }}</div>
    </div>
    <div class="desc">{{ f.description }}</div>
    <div class="rem"><strong>Remédiation :</strong> {{ f.remediation }}</div>
    {% if f.evidence %}<div class="ev">Preuves : {{ f.evidence }}</div>{% endif %}
  </div>
  {% endfor %}

  <footer>argus {{ version }} — sécurité défensive / audit. Corpus de test écrit pour l'exercice.</footer>
</div>
</body>
</html>
""")


def _sev(name: str):
    color, bg, label = _SEV_STYLE.get(name, _SEV_STYLE["info"])
    return {"color": color, "bg": bg, "label": label}


def _offset(value) -> str:
    return f"0x{value:x}" if value is not None else "-"


def render_html(report: Report) -> str:
    elf = report.elf
    prot = elf.protections if elf else {}
    protections = [
        ("NX", bool(prot.get("nx")), ""),
        ("Canary", bool(prot.get("canary")), ""),
        ("PIE", bool(prot.get("pie")), ""),
        ("RELRO", prot.get("relro", "none") != "none", prot.get("relro", "none")),
        ("FORTIFY", bool(prot.get("fortify")), ""),
    ]
    par_sev = (report.stats or {}).get("par_severite", {})
    severites = [(_sev(s), n) for s, n in par_sev.items()]

    findings_ctx = []
    for f in report.findings:
        style = _sev(f.severity.value)
        findings_ctx.append({
            "color": style["color"], "bg": style["bg"], "label": style["label"],
            "score": f.score, "vuln_class": f.vuln_class.value, "function": f.function,
            "static_offset": _offset(f.static_offset), "exploit_offset": _offset(f.exploit_offset),
            "confidence": f.confidence.value,
            "exploitability": f.evidence.get("exploitability", "-"),
            "sources": ", ".join(f.source.split("+")) if f.source else "-",
            "description": f.description, "remediation": f.remediation,
            "evidence": ", ".join(f"{k} = {v}" for k, v in f.evidence.items()),
        })

    return _TEMPLATE.render(
        target=report.target, version=__version__,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
        elf=elf, protections=protections, severites=severites, findings=findings_ctx,
    )


def write_html(report: Report, path: str) -> str:
    """Écrit le rapport HTML dans `path` et renvoie ce chemin."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(report))
    return path
