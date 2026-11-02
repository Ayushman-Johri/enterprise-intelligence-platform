// Safe, dependency-free Markdown renderer: headings, lists (nested), tables, code, quotes, bold/italic, citations.
// All text is HTML-escaped FIRST; only a fixed set of tags is produced. Links and images are never rendered
// (prevents data exfiltration via URLs and XSS via javascript: links).
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function mdInline(s) {
  return esc(s)
    .replace(/&lt;br\s*\/?&gt;/gi, "<br>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
    .replace(/__(.+?)__/g, "<b>$1</b>")
    .replace(/(^|[\s(])\*(?!\s)([^*]+?)\*(?=[\s).,;:!?]|$)/g, "$1<i>$2</i>")
    .replace(/(^|[\s(])_(?!\s)([^_]+?)_(?=[\s).,;:!?]|$)/g, "$1<i>$2</i>")
    .replace(/(?:\[(S\d+)\]\s*)+/g, (m) => m.match(/S\d+/g).map(id => `<span class="cite">${id}</span>`).join("") + " ");
}

function mdCell(raw) {
  let parts = String(raw).split(/\s*<br\s*\/?>\s*/i);
  if (parts.length === 1) parts = String(raw).split(/\s*;\s+(?=[-•*]\s)|\s+(?=•\s)/);
  parts = parts.map(p => p.trim()).filter(Boolean);
  const bullet = /^([-•*]|\d+[.)])\s+/;
  if (parts.length > 1 && parts.filter(p => bullet.test(p)).length >= 2) {
    const lead = bullet.test(parts[0]) ? "" : mdInline(parts.shift());
    return lead + `<ul class="cell-list">${parts.map(p => `<li>${mdInline(p.replace(bullet, ""))}</li>`).join("")}</ul>`;
  }
  return parts.map(mdInline).join("<br>");
}

function md(text) {
  text = String(text ?? "")
    .replace(/【\s*(S\d+)[^】]*】/g, "[$1]").replace(/【/g, "[").replace(/】/g, "]")
    .replace(/\r/g, "");
  const lines = text.split("\n");
  const out = [];
  const isList = (l) => /^\s*([-*•+]|\d+[.)])\s+/.test(l);
  const isTableRow = (l) => /^\s*\|.*\|\s*$/.test(l);
  const isSep = (l) => /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(l || "");
  const cells = (r) => r.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map(c => c.trim());
  let i = 0;
  while (i < lines.length) {
    const l = lines[i];
    if (/^\s*```/.test(l)) {
      const code = []; i++;
      while (i < lines.length && !/^\s*```/.test(lines[i])) code.push(lines[i++]);
      i++; out.push(`<pre>${esc(code.join("\n"))}</pre>`); continue;
    }
    if (isTableRow(l) && isSep(lines[i + 1])) {
      const head = cells(l); i += 2; const body = [];
      while (i < lines.length && isTableRow(lines[i])) body.push(cells(lines[i++]));
      const cls = head.length <= 2 ? "cols-2" : head.length === 3 ? "cols-3" : "cols-n";
      out.push(`<div class="tbl"><table class="${cls}"><thead><tr>${head.map(h => `<th>${mdInline(h)}</th>`).join("")}</tr></thead><tbody>` +
        body.map(r => `<tr>${head.map((_, k) => `<td>${mdCell(r[k] ?? "")}</td>`).join("")}</tr>`).join("") + "</tbody></table></div>");
      continue;
    }
    const h = l.match(/^\s*(#{1,6})\s+(.*)$/);
    if (h) { const lv = h[1].length <= 2 ? 3 : h[1].length === 3 ? 4 : 5; out.push(`<h${lv}>${mdInline(h[2])}</h${lv}>`); i++; continue; }
    if (/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(l)) { out.push("<hr>"); i++; continue; }
    if (/^\s*>\s?/.test(l)) {
      const q = []; while (i < lines.length && /^\s*>\s?/.test(lines[i])) q.push(lines[i++].replace(/^\s*>\s?/, ""));
      out.push(`<blockquote>${q.map(mdInline).join("<br>")}</blockquote>`); continue;
    }
    if (isList(l)) {
      const ordered = /^\s*\d+[.)]/.test(l); const items = [];
      while (i < lines.length && (isList(lines[i]) || (/^\s{2,}\S/.test(lines[i]) && items.length))) {
        const cur = lines[i];
        const topLevel = isList(cur) && !/^\s{2,}/.test(cur);
        if (topLevel && items.length && (/^\s*\d+[.)]/.test(cur) !== ordered)) break;
        i++;
        if (/^\s{2,}([-*•+]|\d+[.)])\s+/.test(cur) && items.length) items[items.length - 1].sub.push(cur.replace(/^\s*([-*•+]|\d+[.)])\s+/, ""));
        else if (isList(cur)) items.push({ t: cur.replace(/^\s*([-*•+]|\d+[.)])\s+/, ""), sub: [] });
        else items[items.length - 1].t += " " + cur.trim();
      }
      const tag = ordered ? "ol" : "ul";
      out.push(`<${tag}>` + items.map(x => `<li>${mdInline(x.t)}${x.sub.length ? `<ul>${x.sub.map(s => `<li>${mdInline(s)}</li>`).join("")}</ul>` : ""}</li>`).join("") + `</${tag}>`);
      continue;
    }
    if (!l.trim()) { i++; continue; }
    const para = [l]; i++;
    while (i < lines.length && lines[i].trim() && !isList(lines[i]) && !/^\s*(#|```|>)/.test(lines[i])
           && !(isTableRow(lines[i]) && isSep(lines[i + 1]))) para.push(lines[i++]);
    out.push(`<p>${para.map(mdInline).join("<br>")}</p>`);
  }
  return out.join("");
}
if (typeof module !== "undefined") module.exports = { md, mdInline, mdCell, esc };
