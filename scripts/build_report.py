from __future__ import annotations

from pathlib import Path


SOURCE = Path("docs/ReconXpose_Internship_Report.md")
HTML_OUT = Path("docs/ReconXpose_Internship_Report.html")


def md_to_html(text: str) -> str:
    lines = text.splitlines()
    out = ["<!doctype html>", "<html><head><meta charset='utf-8'><title>ReconXpose Internship Report</title>",
           "<style>body{font-family:Arial,Helvetica,sans-serif;max-width:980px;margin:40px auto;padding:0 18px;line-height:1.6}h1,h2,h3{color:#0f172a}pre{background:#f4f4f4;padding:12px;overflow:auto;border-radius:8px}code{background:#f4f4f4;padding:2px 4px;border-radius:4px}</style>",
           "</head><body>"]
    in_list = False
    in_code = False
    for line in lines:
        if line.startswith("```"):
            if in_code:
                out.append("</pre>")
                in_code = False
            else:
                out.append("<pre>")
                in_code = True
            continue
        if in_code:
            out.append(line.replace("<", "&lt;").replace(">", "&gt;"))
            continue
        if not line.strip():
            if in_list:
                out.append("</ul>")
                in_list = False
            continue
        if line.startswith("# "):
            out.append(f"<h1>{line[2:]}</h1>")
        elif line.startswith("## "):
            out.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("### "):
            out.append(f"<h3>{line[4:]}</h3>")
        elif line.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{line[2:]}</li>")
        elif line.startswith("***") or line == "---":
            out.append("<hr>")
        else:
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f"<p>{line}</p>")
    if in_list:
        out.append("</ul>")
    out.append("</body></html>")
    return "\n".join(out)


def main() -> None:
    text = SOURCE.read_text(encoding="utf-8")
    HTML_OUT.write_text(md_to_html(text), encoding="utf-8")
    print(f"Wrote {HTML_OUT}")


if __name__ == "__main__":
    main()
