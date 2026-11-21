// 02-api.js: trozo de app.js (v2.8, A-03). Script clasico: comparte el ambito global.
const SESSION_TOKEN = (document.querySelector('meta[name="netwatch-token"]') || {}).content || "";

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (SESSION_TOKEN) headers["X-NetWatch-Token"] = SESSION_TOKEN;
  const res = await fetch(path, { headers, ...opts });
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).detail || msg; } catch (_) {}
    throw new Error(msg);
  }
  return res.json();
}

function toast(msg, type = "") {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className = "show " + type;
  clearTimeout(el._t);
  el._t = setTimeout(() => (el.className = ""), 3600);
}

function askConfirm(text) {
  const dlg = document.getElementById("confirm-dialog");
  if (!dlg || !dlg.showModal) return Promise.resolve(window.confirm(text));
  document.getElementById("confirm-text").textContent = text;
  return new Promise((resolve) => {
    const done = (v) => { dlg.close(); resolve(v); };
    document.getElementById("confirm-ok").onclick = () => done(true);
    document.getElementById("confirm-cancel").onclick = () => done(false);
    dlg.oncancel = () => resolve(false);
    dlg.showModal();
    document.getElementById("confirm-cancel").focus();
  });
}

// S-13: las descargas llevan el token de sesion (window.location no puede).
async function download(path) {
  try {
    const res = await fetch(path, { headers: { "X-NetWatch-Token": SESSION_TOKEN } });
    if (!res.ok) { toast(`La descarga falló (${res.status})`, "err"); return; }
    const cd = res.headers.get("Content-Disposition") || "";
    const m = /filename="?([^";]+)"?/.exec(cd);
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = m ? m[1] : "ai-netwatch-export";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (e) {
    toast(`La descarga falló: ${e.message || e}`, "err");
  }
}

