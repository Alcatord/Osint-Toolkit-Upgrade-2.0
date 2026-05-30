#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import os
from datetime import datetime


class Reporter:
    def __init__(self, display):
        self.display = display

    def print_summary(self, results):
        d = self.display
        d.separator()
        d.section("Analysis Summary")

        d.key_value("Target",           results.get("target", ""))
        d.key_value("Type",             results.get("type", ""))
        d.key_value("Timestamp",        results.get("timestamp", ""))
        d.key_value("Modules executed", str(len(results.get("modules", {}))))

        total_found = sum(
            m.get("found_count", 0)
            for m in results.get("modules", {}).values()
            if isinstance(m, dict)
        )
        d.key_value("Total findings", d.highlight(str(total_found)))
        d.section_end()

    def save(self, results, output_path):
        ext = os.path.splitext(output_path)[1].lower()
        out_dir = os.path.dirname(os.path.abspath(output_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        if ext == ".json":
            self._save_json(results, output_path)
        elif ext == ".html":
            self._save_html(results, output_path)
        else:
            self._save_txt(results, output_path)

    # ── JSON ──────────────────────────────────────────────
    def _save_json(self, results, path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2, default=str)

    # ── TXT ───────────────────────────────────────────────
    def _save_txt(self, results, path):
        lines = [
            "=" * 60,
            "OSINT ANALYZER v2.0 — Analysis Report",
            "=" * 60,
            f"Target    : {results.get('target','')}",
            f"Type      : {results.get('type','')}",
            f"Timestamp : {results.get('timestamp','')}",
            "=" * 60,
        ]
        for mod_name, mod_data in results.get("modules", {}).items():
            lines.append(f"\n[{mod_name.upper()}]")
            lines.append("-" * 40)
            if isinstance(mod_data, dict):
                self._dict_to_lines(mod_data, lines)
            else:
                lines.append(str(mod_data))
        lines += ["", "=" * 60,
                  f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def _dict_to_lines(self, d, lines, indent=0):
        pad = "  " * indent
        for k, v in d.items():
            if isinstance(v, dict):
                lines.append(f"{pad}{k}:")
                self._dict_to_lines(v, lines, indent + 1)
            elif isinstance(v, list):
                lines.append(f"{pad}{k}:")
                for item in v:
                    if isinstance(item, dict):
                        lines.append(f"{pad}  -")
                        self._dict_to_lines(item, lines, indent + 2)
                    else:
                        lines.append(f"{pad}  - {item}")
            else:
                lines.append(f"{pad}{k}: {v}")

    # ── HTML ──────────────────────────────────────────────
    def _save_html(self, results, path):
        target  = results.get("target", "")
        rtype   = results.get("type", "")
        ts      = results.get("timestamp", "")
        mods_html = ""
        for mod_name, mod_data in results.get("modules", {}).items():
            mods_html += (f'<div class="module">'
                          f'<h2>{mod_name.replace("_"," ").title()}</h2>'
                          f'{self._dict_to_html(mod_data)}'
                          f'</div>')

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINT Report — {target}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Tahoma,Arial,sans-serif;background:#0d1117;color:#c9d1d9}}
.header{{background:linear-gradient(135deg,#161b22,#1f2937);padding:2rem;border-bottom:2px solid #30363d}}
.header h1{{color:#58a6ff;font-size:2rem;margin-bottom:.5rem}}
.meta{{color:#8b949e;font-size:.9rem}}
.meta span{{margin-right:1.5rem}}
.container{{max-width:1100px;margin:2rem auto;padding:0 1rem}}
.module{{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:1.5rem;overflow:hidden}}
.module h2{{background:#21262d;padding:.75rem 1.25rem;color:#58a6ff;font-size:1rem;border-bottom:1px solid #30363d}}
.module-body{{padding:1.25rem}}
table{{width:100%;border-collapse:collapse;font-size:.875rem}}
th{{background:#21262d;color:#8b949e;padding:.5rem .75rem;text-align:left;border:1px solid #30363d;font-weight:500}}
td{{padding:.5rem .75rem;border:1px solid #30363d}}
tr:nth-child(even) td{{background:#1a1f26}}
.badge{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.75rem;font-weight:600}}
.badge-found{{background:#1a4731;color:#3fb950}}
.badge-not_found{{background:#3d1f1f;color:#f85149}}
.kv-table td:first-child{{color:#8b949e;width:35%;font-weight:500}}
a{{color:#58a6ff;text-decoration:none}}a:hover{{text-decoration:underline}}
.footer{{text-align:center;color:#8b949e;font-size:.8rem;padding:2rem;border-top:1px solid #30363d;margin-top:2rem}}
</style>
</head>
<body>
<div class="header">
  <h1>🔍 OSINT Report</h1>
  <div class="meta">
    <span>🎯 <strong>{target}</strong></span>
    <span>📌 {rtype}</span>
    <span>🕐 {ts}</span>
  </div>
</div>
<div class="container">{mods_html}</div>
<div class="footer">OSINT Analyzer v2.0 — Open Source Intelligence — {datetime.now().strftime('%Y-%m-%d')}</div>
</body></html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def _dict_to_html(self, data, depth=0):
        if isinstance(data, dict):
            rows = "".join(
                f"<tr><td>{k}</td><td>{self._dict_to_html(v, depth+1)}</td></tr>"
                for k, v in data.items() if k != "found_count"
            )
            cls = "kv-table" if depth == 0 else ""
            return (f'<div class="module-body"><table class="{cls}"><tbody>{rows}</tbody></table></div>'
                    if rows else "<em>(empty)</em>")
        elif isinstance(data, list):
            if not data:
                return "<em>(no results)</em>"
            if all(isinstance(i, dict) for i in data):
                headers = list(data[0].keys())
                hrow = "".join(f"<th>{h}</th>" for h in headers)
                body = ""
                for item in data:
                    cells = ""
                    for h in headers:
                        val = item.get(h, "")
                        sv  = str(val).lower()
                        if sv in ("found","open","yes"):
                            val = '<span class="badge badge-found">✓ Found</span>'
                        elif sv in ("not found","closed","no"):
                            val = '<span class="badge badge-not_found">✗ Not Found</span>'
                        elif str(val).startswith("http"):
                            val = f'<a href="{val}" target="_blank">{val}</a>'
                        cells += f"<td>{val}</td>"
                    body += f"<tr>{cells}</tr>"
                return (f'<div class="module-body"><table>'
                        f'<thead><tr>{hrow}</tr></thead>'
                        f'<tbody>{body}</tbody></table></div>')
            else:
                items = "".join(f"<li>{self._dict_to_html(i, depth+1)}</li>" for i in data)
                return f'<div class="module-body"><ul style="padding-left:1.5rem">{items}</ul></div>'
        elif isinstance(data, bool):
            return ('<span class="badge badge-found">Yes</span>' if data
                    else '<span class="badge badge-not_found">No</span>')
        elif data is None:
            return '<em style="color:#8b949e">N/A</em>'
        else:
            s = str(data)
            return f'<a href="{s}" target="_blank">{s}</a>' if s.startswith("http") else s