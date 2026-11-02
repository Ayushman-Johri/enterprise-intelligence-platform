// API client. Session lives in an HttpOnly cookie (not readable by JS);
// state-changing requests send the CSRF token from the readable eip_csrf cookie.
const API_BASE = window.API_BASE || "";

function readCookie(name) {
  const m = document.cookie.split("; ").find(c => c.startsWith(name + "="));
  return m ? decodeURIComponent(m.split("=").slice(1).join("=")) : "";
}

const Api = {
  async req(path, { method = "GET", body, form } = {}) {
    const headers = {};
    if (body) headers["Content-Type"] = "application/json";
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) headers["X-CSRF-Token"] = readCookie("eip_csrf");
    const res = await fetch(API_BASE + "/api" + path, {
      method, headers, credentials: "same-origin",
      body: form ? form : body ? JSON.stringify(body) : undefined,
    });
    let data = {};
    try { data = await res.json(); } catch (_) {}
    if (res.status === 401 && !path.startsWith("/auth/login") && !path.startsWith("/auth/me")) {
      App.showAuth(); throw new Error("Session expired - please log in again");
    }
    if (!res.ok) {
      let msg = data.error || ("HTTP " + res.status);
      if (data.error_ref) msg += ` (ref ${data.error_ref})`;
      if (res.status === 429 && data.retry_after) msg += ` — retry in ${data.retry_after}s`;
      const err = new Error(msg); err.status = res.status; throw err;
    }
    return data;
  },
  get(p) { return this.req(p); },
  post(p, body) { return this.req(p, { method: "POST", body: body || {} }); },
  del(p) { return this.req(p, { method: "DELETE" }); },
  upload(files) { const f = new FormData(); [...files].forEach(x => f.append("files", x)); return this.req("/documents", { method: "POST", form: f }); },
};
