import html
import re

def markdown_to_html(md: str) -> str:
    """Convert PTES Markdown into clean, semantic HTML with styling."""
    lines = md.splitlines()
    html_out = []
    in_code_block = False
    code_block_lang = ""
    code_block_lines = []
    in_table = False
    table_lines = []

    def flush_table():
        nonlocal in_table, table_lines
        if not table_lines:
            in_table = False
            return
        out = ["<div class='table-wrapper'><table class='report-table'>"]
        # Header row
        header_cols = [c.strip() for c in table_lines[0].strip('|').split('|')]
        out.append("<thead><tr>")
        for col in header_cols:
            out.append(f"<th>{inline_format(col)}</th>")
        out.append("</tr></thead><tbody>")

        for row in table_lines[2:]:
            cols = [c.strip() for c in row.strip('|').split('|')]
            out.append("<tr>")
            for col in cols:
                out.append(f"<td>{inline_format(col)}</td>")
            out.append("</tr>")
        out.append("</tbody></table></div>")
        table_lines = []
        in_table = False
        html_out.append("\n".join(out))

    def inline_format(text: str) -> str:
        # Bold
        text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
        # Italic
        text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
        # Inline code
        text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
        # Links
        text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2" target="_blank">\1</a>', text)
        # Badges
        text = text.replace("🔴 CRITICAL", "<span class='badge badge-crit'>CRITICAL</span>")
        text = text.replace("🟠 HIGH", "<span class='badge badge-high'>HIGH</span>")
        text = text.replace("🟡 MEDIUM", "<span class='badge badge-med'>MEDIUM</span>")
        text = text.replace("🔵 LOW", "<span class='badge badge-low'>LOW</span>")
        text = text.replace("⚪ INFO", "<span class='badge badge-info'>INFO</span>")
        text = text.replace("✅ PASS", "<span class='badge badge-pass'>PASS</span>")
        return text

    for line in lines:
        stripped = line.strip()

        # Code block toggle
        if stripped.startswith("```"):
            if in_code_block:
                code_text = html.escape("\n".join(code_block_lines))
                html_out.append(f"<pre class='code-box'><code class='lang-{code_block_lang}'>{code_text}</code></pre>")
                in_code_block = False
                code_block_lines = []
            else:
                if in_table:
                    flush_table()
                in_code_block = True
                code_block_lang = stripped[3:].strip()
                code_block_lines = []
            continue

        if in_code_block:
            code_block_lines.append(line)
            continue

        # Table detection
        if stripped.startswith("|") and stripped.endswith("|"):
            if not in_table:
                in_table = True
                table_lines = [stripped]
            else:
                table_lines.append(stripped)
            continue
        elif in_table:
            flush_table()

        # Empty lines
        if not stripped:
            continue

        # Headers
        if stripped.startswith("#### "):
            html_out.append(f"<h4>{inline_format(stripped[5:])}</h4>")
        elif stripped.startswith("### "):
            html_out.append(f"<h3>{inline_format(stripped[4:])}</h3>")
        elif stripped.startswith("## "):
            html_out.append(f"<h2>{inline_format(stripped[3:])}</h2>")
        elif stripped.startswith("# "):
            html_out.append(f"<h1>{inline_format(stripped[2:])}</h1>")
        elif stripped.startswith("> "):
            html_out.append(f"<blockquote class='callout'>{inline_format(stripped[2:])}</blockquote>")
        elif stripped == "---":
            html_out.append("<hr class='section-divider'/>")
        elif stripped.startswith("- ") or stripped.startswith("* "):
            html_out.append(f"<li class='bullet-item'>{inline_format(stripped[2:])}</li>")
        else:
            html_out.append(f"<p>{inline_format(stripped)}</p>")

    if in_table:
        flush_table()

    return "\n".join(html_out)

print('Markdown to HTML module compiled cleanly!')

