// ===== helpers (esc, md, mdInline come from markdown.js) =====
const $ = (s) => document.querySelector(s);
function toast(msg, err = false) {
  const t = $("#toast"); t.textContent = msg; t.className = "toast" + (err ? " err" : "");
  setTimeout(() => t.classList.add("hidden"), 4000);
}
const fmt = (n) => Number(n || 0).toLocaleString();
const num = (n, d = 3) => (typeof n === "number" ? n.toFixed(d) : "-");
const shortModel = (m) => String(m || "").replace(/^openai\//, "").replace(/^qwen\//, "");
const safeClass = (s) => String(s || "").replace(/[^a-z0-9_-]/gi, "");

const App = {
  convId: null, pollTimer: null, lastMeta: {}, modelsLoaded: false, authCfg: {},

  async init() {
    this.bindAuth(); this.bindNav(); this.bindDocs(); this.bindChat();
    try { this.authCfg = await Api.get("/auth/config"); } catch (_) { this.authCfg = { registration: true }; }
    if (!this.authCfg.registration) $("#registerTab").classList.add("hidden");
    this.bindInvite();
    try { const { user } = await Api.get("/auth/me"); this.enter(user); } catch (_) { this.showAuth(); }
  },

  // ---------- auth ----------
  authMode: "login",
  bindAuth() {
    document.querySelectorAll("[data-auth]").forEach(b => b.onclick = () => {
      document.querySelectorAll("[data-auth]").forEach(x => x.classList.remove("active"));
      b.classList.add("active"); this.authMode = b.dataset.auth;
      const reg = this.authMode === "register";
      $("#authName").classList.toggle("hidden", !reg);
      $("#authHint").textContent = reg
        ? "Choose an email and password. You can sign in with them right away."
        : "New here? Open Register and create an account. No invite code.";
      $("#authPassword").autocomplete = reg ? "new-password" : "current-password";
      $("#authSubmit").textContent = reg ? "Create account" : "Login";
    });
    $("#authForm").onsubmit = async (e) => {
      e.preventDefault(); $("#authError").textContent = "";
      try {
        const body = { email: $("#authEmail").value, password: $("#authPassword").value };
        if (this.authMode === "register") body.name = $("#authName").value;
        const r = await Api.post("/auth/" + this.authMode, body);
        $("#authPassword").value = "";
        this.enter(r.user);
      } catch (err) { $("#authError").textContent = err.message; }
    };
    $("#logoutBtn").onclick = () => this.logout("/auth/logout");
    $("#logoutAllBtn").onclick = () => { if (confirm("Sign out on all devices?")) this.logout("/auth/logout-all"); };
  },
  showAuth() {
    clearInterval(this.pollTimer);
    $("#authView").classList.remove("hidden"); $("#appView").classList.add("hidden");
  },
  enter(user) {
    this.user = user || null;
    $("#authView").classList.add("hidden"); $("#appView").classList.remove("hidden");
    const role = user && user.role === "admin" ? " · admin" : "";
    $("#userEmail").textContent = user ? user.email + role : "";
    $("#adminNav").classList.toggle("hidden", !(user && user.role === "admin"));
    this.modelsLoaded = false;
    this.route();
  },
  async logout(path) {
    try { await Api.post(path); } catch (_) {}
    this.convId = null; $("#messages").innerHTML = ""; $("#inspector").innerHTML = "";
    this.showAuth();
  },

  // ---------- routing ----------
  bindNav() { window.addEventListener("hashchange", () => this.route()); },
  route() {
    if ($("#appView").classList.contains("hidden")) return;
    let v = (location.hash || "#dashboard").slice(1);
    if (v === "admin" && !(this.user && this.user.role === "admin")) v = "dashboard";
    document.querySelectorAll(".view").forEach(x => x.classList.add("hidden"));
    ($("#view-" + v) || $("#view-dashboard")).classList.remove("hidden");
    document.querySelectorAll("nav a").forEach(a => a.classList.toggle("active", a.dataset.view === v));
    clearInterval(this.pollTimer);
    ({ dashboard: () => this.loadStats(), documents: () => this.loadDocs(), chat: () => this.loadChat(),
       agent: () => this.loadRuns(), logs: () => this.loadLogs(), admin: () => this.loadUsers() }[v] || (() => this.loadStats()))();
  },

  bindInvite() {
    $("#refreshUsers").onclick = () => this.loadUsers();
    $("#inviteForm").onsubmit = async (e) => {
      e.preventDefault();
      $("#inviteResult").textContent = "";
      const email = $("#inviteEmail").value.trim();
      const password = $("#invitePassword").value;
      try {
        await Api.post("/admin/users", { name: $("#inviteName").value.trim(), email, password });
        $("#inviteResult").textContent = "Account created. They sign in with " + email + " and the password you set.";
        $("#inviteForm").reset();
        this.loadUsers();
      } catch (err) { $("#inviteResult").textContent = err.message; }
    };
  },
  async loadUsers() {
    try {
      const { users } = await Api.get("/admin/users");
      $("#userTable").innerHTML = "<tr><th>Email</th><th>Name</th><th>Role</th><th>Created</th></tr>" +
        users.map(u => `<tr><td>${esc(u.email)}</td><td>${esc(u.name || "")}</td><td>${esc(u.role)}</td><td>${esc(u.created_at || "")}</td></tr>`).join("");
    } catch (e) { toast(e.message, true); }
  },

  // ---------- dashboard ----------
  async loadStats() {
    try {
      const s = await Api.get("/stats");
      const d = s.documents, l = s.llm, lim = s.limits || {};
      const cards = [
        ["Documents ready", d.ready || 0], ["Processing", (d.queued || 0) + (d.processing || 0)], ["Failed", d.failed || 0],
        ["Conversations", s.conversations], ["Agent runs", s.agent_runs], ["LLM calls", l.calls],
        ["Total tokens", fmt(l.tokens)], ["Tokens today / budget", `${fmt(lim.tokens_today)} / ${fmt(lim.daily_token_budget)}`],
        ["Avg latency", Math.round(l.avg_latency_ms) + " ms"], ["LLM errors", l.errors], ["Fallbacks used", l.fallbacks],
        ["Cache hits", l.cache_hits], ["Embeddings", s.embeddings],
      ];
      $("#statCards").innerHTML = cards.map(([k, v]) => `<div class="card"><div class="muted small">${esc(k)}</div><div class="big">${esc(v)}</div></div>`).join("");
      const max = Math.max(1, ...s.by_day.map(x => x.tokens || 0));
      $("#tokenChart").innerHTML = s.by_day.length ? s.by_day.map(x =>
        `<div class="bar-row"><span>${esc(x.day.slice(5))}</span><div class="bar" data-w="${(100 * (x.tokens || 0) / max).toFixed(1)}"></div><span>${fmt(x.tokens)}</span></div>`).join("")
        : '<p class="muted">No usage yet</p>';
      // widths set via CSSOM (allowed by the strict CSP, unlike inline style attributes)
      document.querySelectorAll("#tokenChart .bar").forEach(b => { b.style.width = b.dataset.w + "%"; });
      $("#modelTable").innerHTML = "<tr><th>Model</th><th>Calls</th><th>Tokens</th><th>Avg ms</th><th>Errors</th></tr>" +
        (s.by_model.map(m => `<tr><td>${esc(m.model)}</td><td>${m.calls}</td><td>${fmt(m.tokens)}</td><td>${Math.round(m.avg_latency_ms || 0)}</td><td>${m.errors}</td></tr>`).join("")
         || '<tr><td colspan="5" class="muted">No calls yet</td></tr>');
    } catch (e) { toast(e.message, true); }
  },

  // ---------- documents ----------
  bindDocs() {
    const dz = $("#dropZone"), fi = $("#fileInput");
    dz.onclick = () => fi.click();
    fi.onchange = () => this.upload(fi.files);
    dz.ondragover = (e) => { e.preventDefault(); dz.classList.add("over"); };
    dz.ondragleave = () => dz.classList.remove("over");
    dz.ondrop = (e) => { e.preventDefault(); dz.classList.remove("over"); this.upload(e.dataTransfer.files); };
    $("#refreshDocs").onclick = () => this.loadDocs();
  },
  async upload(files) {
    if (!files.length) return;
    $("#uploadResult").textContent = "Uploading…";
    try {
      const r = await Api.upload(files);
      $("#uploadResult").innerHTML = r.results.map(x => `<div>${esc(x.filename)} → <span class="pill st-${safeClass(x.status)}">${esc(x.status)}</span> ${esc(x.error || x.message || "")}</div>`).join("");
      this.loadDocs();
    } catch (e) { $("#uploadResult").textContent = e.message; }
    $("#fileInput").value = "";
  },
  async loadDocs() {
    try {
      const { documents } = await Api.get("/documents");
      $("#docTable").innerHTML = "<tr><th>ID</th><th>File</th><th>Type</th><th>Status</th><th>Chunks</th><th>Injection flags</th><th>Uploaded</th><th></th></tr>" +
        (documents.map(d => `<tr>
          <td>${d.id}</td><td>${esc(d.filename)}</td><td>${esc(d.file_type)}</td>
          <td><span class="pill st-${safeClass(d.status)}">${esc(d.status)}</span>${d.error ? `<div class="error small">${esc(d.error)}</div>` : ""}</td>
          <td>${d.num_chunks}</td><td>${d.injection_flags ? `<button class="btn ghost small warn" data-inj="${d.id}">⚠️ ${d.injection_flags} view</button>` : "—"}</td>
          <td class="small nowrap">${esc(d.created_at)}</td>
          <td class="nowrap"><button class="btn ghost small" data-re="${d.id}">Reprocess</button> <button class="btn danger small" data-del="${d.id}">Delete</button></td></tr>`).join("")
          || '<tr><td colspan="8" class="muted">No documents yet</td></tr>');
      document.querySelectorAll("[data-del]").forEach(b => b.onclick = async () => {
        if (!confirm("Delete this document?")) return;
        try { await Api.del("/documents/" + b.dataset.del); this.loadDocs(); } catch (e) { toast(e.message, true); }
      });
      document.querySelectorAll("[data-re]").forEach(b => b.onclick = async () => {
        try { const r = await Api.post(`/documents/${b.dataset.re}/reprocess`); toast(r.queued ? "Reprocessing queued" : r.reason); this.loadDocs(); }
        catch (e) { toast(e.message, true); }
      });
      document.querySelectorAll("[data-inj]").forEach(b => b.onclick = async () => {
        const { document: d } = await Api.get("/documents/" + b.dataset.inj);
        const bad = d.chunks_preview.filter(c => c.suspicious);
        alert(`Suspected prompt-injection in ${d.filename}:\n\n` + bad.map(c =>
          `• chunk ${c.chunk_index}${c.page ? " (p." + c.page + ")" : ""} — ${c.injection_reasons}\n  "${c.text.slice(0, 160)}…"`).join("\n\n"));
      });
      clearInterval(this.pollTimer);
      if (documents.some(d => ["queued", "processing"].includes(d.status)))
        this.pollTimer = setInterval(() => this.loadDocs(), 2500);
    } catch (e) { toast(e.message, true); }
  },

  // ---------- chat ----------
  bindChat() {
    $("#newConv").onclick = () => { this.convId = null; $("#messages").innerHTML = ""; $("#inspector").innerHTML = ""; this.renderConvs(); };
    $("#chatForm").onsubmit = (e) => { e.preventDefault(); this.send(); };
    $("#chatInput").addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); this.send(); } });
    const setInsp = (show) => { $("#chatLayout").classList.toggle("no-inspector", !show); localStorage.setItem("eip_insp", show ? "1" : "0"); };
    $("#toggleInspector").onclick = () => setInsp($("#chatLayout").classList.contains("no-inspector"));
    $("#closeInspector").onclick = () => setInsp(false);
    setInsp(localStorage.getItem("eip_insp") !== "0");
    $("#modelSelect").onchange = () => localStorage.setItem("eip_model", $("#modelSelect").value);
  },
  async loadModels() {
    if (this.modelsLoaded) return;
    try {
      const { models } = await Api.get("/models");
      const saved = localStorage.getItem("eip_model") || "";
      $("#modelSelect").innerHTML = '<option value="">Auto (primary + fallback)</option>' + models.map(m =>
        `<option value="${esc(m.id)}" ${m.available ? "" : "disabled"}>${esc(m.label)}${m.primary ? " ★" : ""}${m.available ? "" : " — not available for your key"}</option>`).join("");
      if (models.some(m => m.id === saved && m.available)) $("#modelSelect").value = saved;
      this.modelsLoaded = true;
    } catch (e) { /* keep Auto */ }
  },
  async loadChat() {
    try {
      this.loadModels();
      const { documents } = await Api.get("/documents");
      $("#docFilter").innerHTML = '<option value="">All documents</option>' +
        documents.filter(d => d.status === "ready").map(d => `<option value="${d.id}">${esc(d.filename)}</option>`).join("");
      this.renderConvs();
    } catch (e) { toast(e.message, true); }
  },
  async renderConvs() {
    const { conversations } = await Api.get("/conversations");
    $("#convList").innerHTML = conversations.map(c =>
      `<li class="${c.id === this.convId ? "active" : ""}" data-c="${c.id}" title="${esc(c.title)}"><span>${esc(c.title)}</span><button data-dc="${c.id}" title="delete" type="button">×</button></li>`).join("");
    document.querySelectorAll("[data-c]").forEach(li => li.onclick = (e) => { if (!e.target.dataset.dc) this.openConv(+li.dataset.c); });
    document.querySelectorAll("[data-dc]").forEach(b => b.onclick = async () => {
      await Api.del("/conversations/" + b.dataset.dc);
      if (+b.dataset.dc === this.convId) { this.convId = null; $("#messages").innerHTML = ""; }
      this.renderConvs();
    });
  },
  async openConv(id) {
    this.convId = id;
    const { messages } = await Api.get("/conversations/" + id);
    $("#messages").innerHTML = "";
    messages.forEach(m => this.addMsg(m.role, m.content, m.meta));
    this.renderConvs();
  },
  addMsg(role, content, meta) {
    const div = document.createElement("div");
    div.className = "msg " + (role === "user" ? "user" : "assistant");
    let extra = "";
    if (role === "assistant" && meta && Object.keys(meta).length) {
      const key = "m" + Math.random().toString(36).slice(2);
      this.lastMeta[key] = meta;
      const usage = meta.usage || [];
      const tok = usage.reduce((a, u) => a + (u.total_tokens || 0), 0);
      const mainModel = (usage.find(u => u.step === "answer") || usage.find(u => String(u.step).startsWith("agent_step")) || {}).model;
      const fb = usage.some(u => u.fallback_used);
      const v = meta.verification || {};
      const badges = [
        `<span class="pill">${meta.mode === "agent" ? "agent" : "rag"}</span>`,
        meta.status ? `<span class="pill st-${safeClass(meta.status)}">${esc(meta.status)}</span>` : "",
        mainModel ? `<span class="pill model" title="${esc(mainModel)}">${esc(shortModel(mainModel))}${fb ? " ↪" : ""}</span>` : "",
        v.supported === false ? '<span class="pill st-failed">unverified</span>' : "",
        v.supported === true && !v.note ? '<span class="pill st-ready">✔ grounded</span>' : "",
        meta.injection_warnings ? `<span class="pill st-failed" title="Instructions found inside a document were neutralised">⚠️ ${meta.injection_warnings} suspicious source(s)</span>` : "",
      ].join(" ");
      extra = `<div class="msg-meta">${badges} <span class="muted small">${fmt(tok)} tokens • ${fmt(meta.latency_ms)} ms</span>
               <button class="btn ghost small" data-meta="${key}" type="button">details</button></div>`;
      if (meta.sources && meta.sources.length) {
        const shown = meta.sources.filter(s => !meta.citations || !meta.citations.length || meta.citations.includes(s.source_id));
        extra += `<div class="sources">` + shown.map(s =>
          `<span class="src${s.suspicious ? " sus" : ""}" title="${esc(s.snippet)}"><b>${esc(s.source_id)}</b> ${esc(s.filename)}${s.page ? " · p." + s.page : ""}${s.suspicious ? " ⚠️" : ""}</span>`).join("") + "</div>";
      }
      if (meta.report) extra += this.renderReport(meta.report);
    }
    div.innerHTML = `<div class="bubble ${role === "assistant" ? "md" : ""}">${role === "assistant" ? md(content) : esc(content).replace(/\n/g, "<br>")}</div>${extra}`;
    $("#messages").appendChild(div);
    div.querySelectorAll("[data-meta]").forEach(b => b.onclick = () => this.inspect(this.lastMeta[b.dataset.meta], true));
    $("#messages").scrollTop = $("#messages").scrollHeight;
  },
  renderReport(r) {
    return `<div class="report"><h4>📄 ${esc(r.title || "Report")}</h4>
      <div class="sec">Executive summary</div><p>${mdInline(r.executive_summary || "")}</p>
      <div class="sec">Findings</div><ol>${(r.findings || []).map(f => `<li><b>${mdInline(f.title || "")}</b> — ${mdInline(f.detail || "")}${f.evidence ? `<div class="evidence">Evidence: ${mdInline(f.evidence)}</div>` : ""}</li>`).join("")}</ol>
      <div class="sec">Recommendations</div><ul class="recs">${(r.recommendations || []).map(x => `<li><span class="pill pr-${safeClass(x.priority)}">${esc(x.priority || "")}</span> ${mdInline(x.action || "")}${x.rationale ? `<div class="muted small">${mdInline(x.rationale)}</div>` : ""}</li>`).join("")}</ul>
      ${(r.risks_and_gaps || []).length ? `<div class="sec">Risks &amp; gaps</div><ul>${r.risks_and_gaps.map(x => `<li>${mdInline(x)}</li>`).join("")}</ul>` : ""}</div>`;
  },
  inspect(meta, open = false) {
    if (open) { $("#chatLayout").classList.remove("no-inspector"); localStorage.setItem("eip_insp", "1"); }
    let h = "";
    if (meta.retrieval) h += `<h4>Retrieval</h4><div class="kv"><span>Strategy</span><b>${esc(meta.retrieval.strategy || "-")}</b>
      <span>Scoped to previous docs</span><b>${esc(meta.retrieval.scoped_to_previous_docs)}</b><span>Relevance gate</span><b>${esc(meta.retrieval.relevance_gate)}</b></div>
      <div class="muted">Query used:</div><code class="block">${esc(meta.retrieval.query_used)}</code>`;
    if (meta.verification) h += `<h4>Verification</h4><pre>${esc(JSON.stringify(meta.verification, null, 2))}</pre>`;
    if (meta.conflicts && meta.conflicts.length) h += `<h4>Conflicts</h4><pre>${esc(JSON.stringify(meta.conflicts, null, 2))}</pre>`;
    if (meta.steps) h += `<h4>Agent steps</h4>` + meta.steps.map(s => `<details class="step" ${s.error ? "open" : ""}>
        <summary><b>#${esc(s.step)} ${esc(s.tool || s.type)}</b> ${s.status ? `<span class="pill st-${safeClass(s.status)}">${esc(s.status)}</span>` : ""} <span class="muted">${s.duration_ms != null ? esc(s.duration_ms) + " ms" : ""}</span></summary>
        ${s.output_preview ? `<div class="preview">→ ${esc(s.output_preview)}</div>` : ""}
        ${s.args ? `<pre>${esc(JSON.stringify(s.args, null, 1))}</pre>` : ""}
        ${s.error ? `<div class="error">${esc(s.error)}</div>` : ""}</details>`).join("");
    if (meta.sources && meta.sources.length) h += `<h4>Sources</h4>` + meta.sources.map(s => `<details class="srcbox">
        <summary><b>${esc(s.source_id)}</b> ${esc(s.filename)} ${s.page ? "· p." + s.page : ""} ${s.suspicious ? "⚠️" : ""}</summary>
        <div class="muted">vec ${num(s.vector_score)} • bm25 ${num(s.bm25_score, 2)} • rrf ${num(s.fused_score, 4)}</div>
        ${s.suspicious ? `<div class="error small">Injection reasons: ${esc(s.injection_reasons)}</div>` : ""}
        <div>${esc(s.snippet)}…</div></details>`).join("");
    if (meta.usage) h += `<h4>Token usage</h4><table class="usage"><tr><th>Step</th><th>Model</th><th>Tok</th><th>ms</th></tr>` +
      meta.usage.map(u => `<tr><td>${esc(u.step)}</td><td>${esc(shortModel(u.model))}${u.fallback_used ? " ↪" : ""}${u.cached ? " ⚡" : ""}</td><td>${esc(u.total_tokens)}</td><td>${esc(u.latency_ms)}</td></tr>`).join("") + "</table>";
    $("#inspector").innerHTML = h || "No details";
  },
  async send() {
    const text = $("#chatInput").value.trim();
    if (!text || $("#sendBtn").disabled) return;
    $("#chatInput").value = ""; $("#sendBtn").disabled = true;
    this.addMsg("user", text);
    const thinking = document.createElement("div"); thinking.className = "msg assistant";
    thinking.innerHTML = `<div class="bubble muted"><span class="spinner"></span> ${$("#chatMode").value === "agent" ? "Agent is working (searching, analysing, reporting)…" : "Retrieving evidence and generating answer…"}</div>`;
    $("#messages").appendChild(thinking);
    $("#messages").scrollTop = $("#messages").scrollHeight;
    try {
      const body = { message: text, mode: $("#chatMode").value, conversation_id: this.convId };
      if ($("#modelSelect").value) body.model = $("#modelSelect").value;
      if ($("#docFilter").value) body.document_ids = [+$("#docFilter").value];
      const r = await Api.post("/chat", body);
      thinking.remove();
      const isNew = !this.convId; this.convId = r.conversation_id;
      const { answer, ...meta } = r; meta.mode = r.mode;
      this.addMsg("assistant", answer, meta); this.inspect(meta);
      if (isNew) this.renderConvs();
    } catch (e) { thinking.innerHTML = `<div class="bubble error">${esc(e.message)}</div>`; }
    $("#sendBtn").disabled = false;
  },

  // ---------- agent runs ----------
  async loadRuns() {
    try {
      const { runs } = await Api.get("/agent/runs");
      $("#agentRuns").innerHTML = runs.map(r => `<div class="panel"><div class="row-between"><b>${esc(r.task)}</b><span class="pill st-${safeClass(r.status)}">${esc(r.status)}</span></div>
        <div class="muted small">${esc(r.created_at)}</div><ol class="steps">${r.steps.map(s => `<li><b>${esc(s.tool || s.type)}</b> ${s.status ? `<span class="pill st-${safeClass(s.status)}">${esc(s.status)}</span>` : ""} <span class="muted">${esc(s.output_preview || s.error || s.note || "")}</span></li>`).join("")}</ol></div>`).join("")
        || '<p class="muted">No agent runs yet. Use Agent mode in AI Chat.</p>';
    } catch (e) { toast(e.message, true); }
  },

  // ---------- logs ----------
  async loadLogs() {
    try {
      const l = await Api.get("/logs?limit=100");
      $("#llmLogTable").innerHTML = "<tr><th>Time</th><th>Purpose</th><th>Model</th><th>Tokens</th><th>ms</th><th>OK</th><th>Fallback</th><th>Cache</th><th>Error</th></tr>" +
        l.llm_calls.map(c => `<tr class="${c.success ? "" : "row-err"}"><td class="small nowrap">${esc(c.created_at)}</td><td>${esc(c.purpose)}</td><td class="nowrap">${esc(c.model)}</td><td>${esc(c.total_tokens)}</td><td>${esc(c.latency_ms)}</td><td>${c.success ? "✔" : "✖"}</td><td>${c.fallback_used ? "↪" : ""}</td><td>${c.cached ? "⚡" : ""}</td><td class="small err-cell" title="${esc(c.error || "")}">${esc(c.error || "")}</td></tr>`).join("");
      $("#activityTable").innerHTML = "<tr><th>Time</th><th>Level</th><th>Action</th><th>Detail</th></tr>" +
        l.activity.map(a => `<tr class="${a.level === "error" ? "row-err" : a.level === "warning" ? "row-warn" : ""}"><td class="small nowrap">${esc(a.created_at)}</td><td>${esc(a.level)}</td><td>${esc(a.action)}</td><td class="small err-cell" title="${esc(a.detail || "")}">${esc(a.detail || "")}</td></tr>`).join("");
    } catch (e) { toast(e.message, true); }
  },
};

App.init();
