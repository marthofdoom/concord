// Concord console. Every byte from the server is untrusted: it only ever
// reaches the page through textContent / createElement, never as markup.
import {
  attention, buildQuery, countBy, distinct, epochs, estateOutcome, filterGuests, fmtAgo, fmtBytes, fmtDuration,
  freshness, guestBadge, guestResult, signOutOutcome, guestHref, guestRows, hostBadge, loginOutcome, parseHash, pct, sortGuests, tfaAnswer,
} from "/ui/logic.js";

const REFRESH_MS = 5000;
const root = document.getElementById("app");

const S = {
  user: null,          // {user, role} once signed in
  estate: null,        // last good estate
  fetchedAt: null,     // unix secs of last successful fetch
  fetchOk: true,       // did the latest fetch reach the controller
  waiting: false,      // 503: first cycle not done
  error: null,         // text for the latest failure
  notice: null,        // text that stays until acted on
  guest: null,         // {key, data, error, status}
  view: null,          // {key, update()} for the mounted route
};
const sessions = epochs();
const now = () => Math.floor(Date.now() / 1000);

// ---- DOM helpers (text only) ----
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k in el && k !== "list") el[k] = v;
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const badge = (b) => h("span", { class: "badge " + b.cls }, h("span", { "aria-hidden": "true", text: b.glyph }), " " + b.text);
const link = (href, text) => h("a", { href, text });
function replace(el, ...kids) { el.replaceChildren(...kids.flat().filter((k) => k !== null && k !== undefined && k !== false)); }

// ---- API ----
const API_TIMEOUT_MS = 8000;
// A PVE host that does not answer is waited for, and its queue before that.
const LOGIN_TIMEOUT_MS = 25000;
class Unauthorized extends Error {}
async function api(path, opts = {}) {
  const method = opts.method || "GET";
  const headers = { Accept: "application/json" };
  if (method !== "GET") headers["X-Concord-Request"] = "1";
  if (opts.body) headers["Content-Type"] = "application/json";
  // Without a deadline a connection that hangs, rather than fails, would leave
  // the last picture on screen looking live.
  const current = sessions.start();
  const signal = AbortSignal.timeout(opts.timeout || API_TIMEOUT_MS);
  const r = await fetch(path, { method, headers, body: opts.body, credentials: "same-origin", cache: "no-store", signal });
  if (r.status === 401 && !opts.allow401) { if (current()) signedOut(); throw new Unauthorized(); }
  return r;
}
async function json(r) { try { return await r.json(); } catch { return null; } }

function signedOut() {
  sessions.end();
  inflight = false; S.notice = null;
  S.user = null;
  S.view = null;
  // The next login may be another user or a restarted controller: the old
  // picture must not be repainted as if it were current.
  S.estate = null; S.guest = null; S.fetchedAt = null;
  S.waiting = false; S.fetchOk = true; S.error = null;
  renderShell();
}

// ---- refresh ----
let inflight = false;
async function refresh() {
  if (!S.user || inflight) return;
  inflight = true;
  const current = sessions.start();
  try {
    const r = await api("/api/v1/estate");
    const body = await json(r);
    if (!current()) return;
    const o = estateOutcome(r.status, body);
    S.waiting = o.kind === "starting";
    S.fetchOk = o.kind !== "failed";
    S.error = o.error || null;
    if (o.kind === "starting") S.estate = null;
    if (o.kind === "ok") { S.estate = body; S.fetchedAt = now(); }
    await refreshGuest(current);
  } catch (e) {
    if (e instanceof Unauthorized || !current()) return;
    S.waiting = false;
    S.fetchOk = false;
    S.error = "no answer from the controller";
  } finally {
    // A later sign-in's refresh is not this one's to unmark.
    if (current()) inflight = false;
  }
  if (current()) paint();
}

async function refreshGuest(current) {
  const { path } = parseHash(location.hash);
  if (path[0] !== "guests" || path.length < 3) { S.guest = null; return; }
  const key = path[1] + "/" + path[2];
  try {
    const r = await api(`/api/v1/guests/${encodeURIComponent(path[1])}/${encodeURIComponent(path[2])}`);
    const body = await json(r);
    if (!current()) return;
    S.guest = { key, ...guestResult(r.status, body) };
  } catch (e) {
    if (e instanceof Unauthorized || !current()) throw e;
    // Drop the old detail: the view falls back to the fresh estate copy and
    // says the detail could not be loaded, rather than showing it as current.
    S.guest = { key, ...guestResult(0, null) };
  }
}

// ---- shell ----
let els = {};
function renderShell() {
  els = {};
  if (!S.user) { renderLogin(); return; }
  els.banner = h("div", { id: "banner", role: "status" });
  els.updated = h("span", { class: "updated" });
  els.main = h("main", { id: "main", tabindex: "-1" });
  els.nav = h("nav", { "aria-label": "Sections" },
    ["overview:Overview:#/", "hosts:Hosts:#/hosts", "guests:Guests:#/guests"].map((s) => {
      const [id, label, href] = s.split(":");
      return h("a", { href, "data-nav": id, text: label });
    }));
  replace(root,
    h("header", { class: "top" },
      h("div", { class: "brand" }, h("img", { src: "/ui/favicon.svg", alt: "", width: 20, height: 20 }), h("span", { text: "Concord" })),
      els.nav,
      h("div", { class: "who" },
        els.updated,
        h("span", { class: "role", title: "Signed in as " + S.user.user }, S.user.user + " · " + S.user.role),
        h("button", { type: "button", class: "quiet", text: "Sign out", onclick: signOut }))),
    els.banner, els.main);
  route(true);
  refresh();
}

function renderLogin() {
  const err = h("p", { class: "err", role: "alert" });
  const user = h("input", { id: "u", name: "username", autocomplete: "username", required: true, autofocus: true });
  const pw = h("input", { id: "p", name: "password", type: "password", autocomplete: "current-password", required: true });
  const btn = h("button", { type: "submit", text: "Sign in" });
  const submit = async (e) => {
    e.preventDefault();
    btn.disabled = true; err.textContent = "";
    try {
      const o = await postSession({ username: user.value, password: pw.value });
      if (o.kind === "in") { pw.value = ""; await loadSession(); return; }
      if (o.kind === "tfa") { pw.value = ""; renderTfa(o); return; }
      err.textContent = o.error;
    } catch { err.textContent = "Cannot reach the Concord controller."; }
    pw.value = ""; btn.disabled = false;
  };
  const form = h("form", { class: "login card", onsubmit: submit },
    h("h1", { text: "Concord" }),
    h("p", { class: "muted", text: "Sign in to the estate console." }),
    h("label", { for: "u", text: "Username" }), user,
    h("label", { for: "p", text: "Password" }), pw,
    err, btn,
    h("p", { class: "muted small", text: "A Concord user, or root@host for a tracked Proxmox VE host, with that host's root password (if enabled)." }));
  replace(root, h("main", { class: "login-wrap", id: "main" }, form));
  user.focus();
}

async function postSession(body) {
  const r = await api("/api/v1/session", { method: "POST", allow401: true, timeout: LOGIN_TIMEOUT_MS, body: JSON.stringify(body) });
  return loginOutcome(r.status, r.status === 204 ? null : await json(r));
}

// The challenge lives here only, and is good for one answer.
function renderTfa({ challenge, kinds }) {
  const label = { totp: "Code from your authenticator", recovery: "Recovery key" };
  const err = h("p", { class: "err", role: "alert" });
  const kind = h("select", { id: "k" }, kinds.map((k) => h("option", { value: k, text: label[k] })));
  const code = h("input", { id: "c", name: "code", autocomplete: "one-time-code", required: true });
  const codeLabel = h("label", { for: "c" });
  const btn = h("button", { type: "submit", text: "Continue" });
  const again = h("button", { type: "button", class: "quiet", text: "Start over", onclick: renderLogin });
  const show = () => { codeLabel.textContent = label[kind.value]; code.inputMode = kind.value === "totp" ? "numeric" : "text"; code.value = ""; };
  kind.addEventListener("change", show);
  const submit = async (e) => {
    e.preventDefault();
    const tfa = tfaAnswer(kind.value, code.value);
    if (!tfa) { err.textContent = "That does not look like a " + (kind.value === "totp" ? "code." : "recovery key."); return; }
    btn.disabled = true; again.disabled = true; err.textContent = "";
    let why;
    try {
      const o = await postSession({ challenge, tfa });
      if (o.kind === "in") { code.value = ""; await loadSession(); return; }
      why = o.error === "Wrong username or password." || !o.error ? "Second factor refused." : o.error;
    } catch { why = "Cannot reach the Concord controller."; }
    renderLogin();
    const el = root.querySelector(".err"); if (el) el.textContent = why + " Sign in again.";
  };
  replace(root, h("main", { class: "login-wrap", id: "main" }, h("form", { class: "login card", onsubmit: submit },
    h("h1", { text: "Concord" }),
    h("p", { class: "muted", text: "This account has a second factor." }),
    kinds.length > 1 ? [h("label", { for: "k", text: "Kind" }), kind] : null,
    codeLabel, code, err, btn, again)));
  show();
  code.focus();
}

async function loadSession() {
  try {
    const r = await api("/api/v1/session", { allow401: true });
    if (r.ok) { const b = await json(r); if (b && b.user) { S.user = { user: String(b.user), role: String(b.role) }; renderShell(); return; } }
    S.user = null; renderShell();
  } catch {
    S.user = null; renderShell();
    const e = root.querySelector(".err"); if (e) e.textContent = "Cannot reach the Concord controller.";
  }
}

async function signOut() {
  let status = 0;
  try { status = (await api("/api/v1/session", { method: "DELETE", allow401: true })).status; } catch { /* reported below */ }
  if (signOutOutcome(status) === "failed") {
    // The session cookie is still live; showing the login page would lie.
    S.notice = "You are still signed in" + (status ? " (HTTP " + status + ")" : " (no answer from the controller)") + ". Try again.";
    paint();
    return;
  }
  signedOut();
}

// ---- status strip, banner, staleness ----
function paint() {
  if (!S.user || !els.main) return;
  const t = now();
  const fr = S.estate ? freshness({ fetchOk: S.fetchOk, takenAt: S.estate.taken_at, nowSecs: t, waiting: S.waiting }) : (S.fetchOk ? "live" : "unreachable");
  const notes = [];
  if (S.notice) notes.push(h("div", { class: "banner bad" }, h("strong", { text: "✕ Sign-out failed. " }), S.notice));
  if (fr === "unreachable") {
    notes.push(h("div", { class: "banner bad" }, h("strong", { text: "✕ Controller unreachable. " }),
      S.error + ". ", S.estate ? "The data below is from " + fmtAgo(S.fetchedAt, t) + " and is not current." : "Nothing to show yet."));
  } else if (fr === "old") {
    notes.push(h("div", { class: "banner bad" }, h("strong", { text: "▲ Inventory is old. " }),
      "The controller answers, but its last cycle finished " + fmtAgo(S.estate.taken_at, t) + ". What follows may not reflect the estate."));
  }
  if (S.waiting) notes.push(h("div", { class: "banner warn" }, h("strong", { text: "○ Starting up. " }), "The controller has not finished its first inventory cycle yet."));
  replace(els.banner, notes);
  els.main.classList.toggle("is-stale", fr !== "live");
  els.updated.textContent = S.fetchedAt ? "Updated " + fmtAgo(S.fetchedAt, t) : "Not updated yet";
  els.updated.className = "updated" + (fr !== "live" ? " bad" : "");
  if (S.view) S.view.update();
}
setInterval(() => { if (S.user && !document.hidden) paint(); }, 1000);
setInterval(() => { if (!document.hidden) refresh(); }, REFRESH_MS);
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });

// ---- routing ----
window.addEventListener("hashchange", () => route(false));
function route(first) {
  if (!S.user || !els.main) return;
  const { path, query } = parseHash(location.hash);
  const [a, b, c] = path;
  let view;
  let nav = "overview";
  if (!a) view = overviewView();
  else if (a === "hosts" && !b) { nav = "hosts"; view = hostsView(); }
  else if (a === "hosts") { nav = "hosts"; view = hostView(b); }
  else if (a === "guests" && b && c) { nav = "guests"; view = guestView(b, c); S.guest = null; }
  else if (a === "guests") { nav = "guests"; view = guestsView(query); }
  else view = notFoundView();
  for (const l of els.nav.querySelectorAll("a")) {
    if (l.dataset.nav === nav) l.setAttribute("aria-current", "page"); else l.removeAttribute("aria-current");
  }
  S.view = view;
  replace(els.main, view.el);
  document.title = view.title + " · Concord";
  if (!first) { window.scrollTo(0, 0); els.main.focus({ preventScroll: true }); }
  paint();
  if (a === "guests" && b && c) refresh();
}

function waitingView(what) {
  if (S.waiting) return h("p", { class: "empty", text: "Waiting for the first inventory cycle." });
  return h("p", { class: "empty", text: S.error ? "No data yet: " + S.error + "." : "Loading " + what + "…" });
}

// ---- overview ----
function overviewView() {
  const box = h("div");
  return { title: "Overview", el: h("div", {}, h("h1", { text: "Overview" }), box), update() {
    const e = S.estate;
    if (!e) { replace(box, waitingView("the estate")); return; }
    const t = now();
    const rows = guestRows(e);
    const hostCounts = { ok: 0, degraded: 0, unreachable: 0, pending: 0 };
    for (const x of e.hosts) hostCounts[hostBadge({ ...x, stale_guests: x.guests.filter((g) => g.stale).length }).text]++;
    const gc = countBy(rows, "status");
    const items = attention(e, t);
    replace(box,
      h("section", { class: "card attn", "aria-labelledby": "attn-h" },
        h("h2", { id: "attn-h", text: items.length ? "Needs attention (" + items.length + ")" : "Needs attention" }),
        items.length ? h("ul", { class: "attn-list" }, items.map((it) =>
          h("li", { class: it.level }, h("span", { class: "badge " + it.level }, h("span", { "aria-hidden": "true", text: it.level === "bad" ? "✕" : "▲" }), it.level === "bad" ? " problem" : " warning"),
            " ", link(it.href, it.text), h("div", { class: "why", text: it.why }))))
          : h("p", { class: "ok" }, h("span", { "aria-hidden": "true", text: "● " }), "Nothing needs attention.")),
      h("div", { class: "grid" },
        h("section", { class: "card" }, h("h2", { text: "Hosts" }),
          h("p", { class: "big", text: String(e.hosts.length) }),
          h("ul", { class: "tally" },
            ["ok", "degraded", "unreachable", "pending"].filter((k) => k === "ok" || hostCounts[k] > 0).map((k) =>
              h("li", {}, badge(hostBadge({ status: k === "degraded" ? "ok" : k, stale_guests: k === "degraded" ? 1 : 0 })), h("span", { class: "n", text: String(hostCounts[k]) })))),
          link("#/hosts", "All hosts")),
        h("section", { class: "card" }, h("h2", { text: "Guests" }),
          h("p", { class: "big", text: String(rows.length) }),
          h("ul", { class: "tally" }, Object.keys(gc).sort().map((k) =>
            h("li", {}, badge(guestBadge({ status: k })), h("span", { class: "n", text: String(gc[k]) })))),
          link("#/guests", "All guests")),
        h("section", { class: "card" }, h("h2", { text: "VMID conflicts" }),
          h("p", { class: "big", text: String(e.conflicts.length) }),
          e.conflicts.length ? h("ul", {}, e.conflicts.map((c) => h("li", {}, link("#/guests?q=" + c.vmid, "VMID " + c.vmid), " on " + c.hosts.join(", "))))
            : h("p", { class: "muted", text: "Every VMID is unique across the estate." }))),
      h("p", { class: "muted small", text: "Inventory cycle " + e.cycle + ", finished " + fmtAgo(e.taken_at, t) + "." }));
  } };
}

// ---- hosts ----
function hostsView() {
  const box = h("div");
  return { title: "Hosts", el: h("div", {}, h("h1", { text: "Hosts" }), box), update() {
    const e = S.estate;
    if (!e) { replace(box, waitingView("hosts")); return; }
    const t = now();
    replace(box, h("div", { class: "tablewrap" }, h("table", { class: "dense" },
      h("thead", {}, h("tr", {}, ["Host", "Status", "PVE", "Guests", "Last good poll", "Detail"].map((x) => h("th", { scope: "col", text: x })))),
      h("tbody", {}, e.hosts.map((x) => {
        const stale = x.guests.filter((g) => g.stale).length;
        const b = hostBadge({ ...x, stale_guests: stale });
        return h("tr", {},
          h("th", { scope: "row" }, link("#/hosts/" + encodeURIComponent(x.name), x.name)),
          h("td", {}, badge(b)), h("td", { text: x.pve_version || "n/a" }),
          h("td", { text: x.guests.length + (stale ? " (" + stale + " stale)" : "") }),
          h("td", { text: fmtAgo(x.last_success ?? undefined, t) }),
          h("td", { class: x.error ? "err" : "muted", text: x.error || "" }));
      })))));
  } };
}

function kv(pairs) {
  return h("dl", { class: "kv" }, pairs.flatMap(([k, v]) => [h("dt", { text: k }), h("dd", {}, v)]));
}

function hostView(name) {
  const box = h("div");
  return { title: "Host " + name, el: h("div", {}, h("p", { class: "crumb" }, link("#/hosts", "Hosts"), " / ", name), h("h1", { text: name }), box), update() {
    const e = S.estate;
    if (!e) { replace(box, waitingView("the host")); return; }
    const x = e.hosts.find((y) => y.name === name);
    if (!x) { replace(box, h("p", { class: "empty", text: "No host named “" + name + "” in the inventory." })); return; }
    const t = now();
    const stale = x.guests.filter((g) => g.stale).length;
    replace(box,
      h("section", { class: "card" }, kv([
        ["Status", badge(hostBadge({ ...x, stale_guests: stale }))],
        ["Why", x.error ? h("span", { class: "err", text: x.error }) : "No fault reported"],
        ["PVE node", x.node || "n/a"], ["PVE version", x.pve_version || "n/a"],
        ["Last good poll", fmtAgo(x.last_success ?? undefined, t)],
        ["Guests", x.guests.length + (stale ? ", " + stale + " with stale data" : "")]])),
      x.status === "unreachable" ? h("p", { class: "banner bad" }, "This host did not answer. The guests below are the last known values, not current state.") : null,
      h("h2", { text: "Guests on " + name }),
      guestTable(x.guests.map((g) => ({ ...g, host: x.name })), null));
  } };
}

// ---- guests table ----
function guestTable(rows, sortState) {
  const th = (label, key) => {
    if (!sortState) return h("th", { scope: "col", text: label });
    const on = sortState.key === key;
    return h("th", { scope: "col", "aria-sort": on ? (sortState.dir === "desc" ? "descending" : "ascending") : "none" },
      h("button", { type: "button", class: "sort", onclick: () => sortState.set(key) }, label, on ? (sortState.dir === "desc" ? " ▾" : " ▴") : ""));
  };
  return h("div", { class: "tablewrap" }, h("table", { class: "dense" },
    h("thead", {}, h("tr", {}, [th("VMID", "vmid"), th("Name", "name"), th("Host", "host"), th("Kind", "kind"), th("Status", "status"), th("CPUs", "cpus"), th("Memory", "mem"), th("Uptime", "uptime")])),
    h("tbody", {}, rows.map((g) => h("tr", { class: g.stale ? "stale-row" : "" },
      h("td", { class: "num" }, link(guestHref(g.host, g.vmid), String(g.vmid))),
      h("td", {}, g.name || h("span", { class: "muted", text: "(unnamed)" }), g.template ? h("span", { class: "tag", text: "template" }) : null),
      h("td", {}, link("#/hosts/" + encodeURIComponent(g.host), g.host)),
      h("td", { text: g.kind }),
      h("td", {}, badge(guestBadge(g)), g.stale ? h("span", { class: "badge warn" }, h("span", { "aria-hidden": "true", text: "▲" }), " stale") : null),
      h("td", { class: "num", text: g.cpus ?? "n/a" }),
      h("td", { class: "num", text: g.mem !== null && g.mem !== undefined ? fmtBytes(g.mem) : "n/a" }),
      h("td", { class: "num", text: g.status === "running" ? fmtDuration(g.uptime) : "" }))))));
}

function guestsView(initial) {
  const f = { q: initial.q || "", host: initial.host || "", kind: initial.kind || "", status: initial.status || "", sort: initial.sort || "vmid", dir: initial.dir === "desc" ? "desc" : "asc" };
  const sync = () => {
    const q = buildQuery({ q: f.q, host: f.host, kind: f.kind, status: f.status, sort: f.sort === "vmid" ? "" : f.sort, dir: f.dir === "desc" ? "desc" : "" });
    history.replaceState(null, "", "#/guests" + q);
  };
  const q = h("input", { type: "search", id: "gq", value: f.q, placeholder: "VMID, name, host, tag", "aria-label": "Search guests", oninput: () => { f.q = q.value; sync(); render(); } });
  const mk = (id, label, key) => {
    const sel = h("select", { id, "aria-label": label, onchange: () => { f[key] = sel.value; sync(); render(); } });
    return sel;
  };
  const host = mk("gh", "Host", "host"), kind = mk("gk", "Kind", "kind"), status = mk("gs", "Status", "status");
  const count = h("p", { class: "muted small", "aria-live": "polite" });
  const tableBox = h("div");
  const fill = (sel, label, key, values) => {
    // Rebuilt only when the option set changes, so an open dropdown is not disturbed.
    const sig = values.join("\n") + "|" + f[key];
    if (sel.dataset.sig === sig) return;
    sel.dataset.sig = sig;
    const vals = f[key] && !values.includes(f[key]) ? [...values, f[key]] : values;
    replace(sel, h("option", { value: "", text: "All " + label }), vals.map((v) => h("option", { value: v, text: v })));
    sel.value = f[key];
  };
  const sortState = { get key() { return f.sort; }, get dir() { return f.dir; }, set(key) {
    if (f.sort === key) f.dir = f.dir === "asc" ? "desc" : "asc"; else { f.sort = key; f.dir = "asc"; }
    sync(); render();
  } };
  function render() {
    const e = S.estate;
    if (!e) { replace(tableBox, waitingView("guests")); return; }
    const all = guestRows(e);
    fill(host, "hosts", "host", distinct(all, "host"));
    fill(kind, "kinds", "kind", ["lxc", "qemu"]);
    fill(status, "statuses", "status", distinct(all, "status"));
    const rows = sortGuests(filterGuests(all, f), f.sort, f.dir);
    count.textContent = rows.length + " of " + all.length + " guests";
    replace(tableBox, rows.length ? guestTable(rows, sortState) : h("p", { class: "empty", text: all.length ? "No guest matches these filters." : "The estate has no guests." }));
  }
  const bar = h("div", { class: "filters" },
    h("label", { class: "grow" }, h("span", { text: "Search" }), q),
    h("label", {}, h("span", { text: "Host" }), host), h("label", {}, h("span", { text: "Kind" }), kind), h("label", {}, h("span", { text: "Status" }), status),
    h("button", { type: "button", class: "quiet", text: "Clear", onclick: () => { Object.assign(f, { q: "", host: "", kind: "", status: "" }); q.value = ""; sync(); render(); } }));
  return { title: "Guests", el: h("div", {}, h("h1", { text: "Guests" }), bar, count, tableBox), update: render };
}

// ---- guest page ----
function guestView(host, vmid) {
  const box = h("div");
  const key = host + "/" + vmid;
  return { title: "Guest " + vmid, el: h("div", {}, h("p", { class: "crumb" }, link("#/guests", "Guests"), " / ", link("#/hosts/" + encodeURIComponent(host), host), " / " + vmid), box), update() {
    const d = S.guest && S.guest.key === key ? S.guest : null;
    const fromEstate = S.estate && (S.estate.hosts.find((x) => x.name === host) || { guests: [] }).guests.find((g) => String(g.vmid) === vmid);
    const g = (d && d.data) || fromEstate;
    if (!g) {
      replace(box, d && d.status === 404 ? h("p", { class: "empty", text: "No guest " + vmid + " on host “" + host + "”." }) : waitingView("the guest"));
      return;
    }
    const t = now();
    const hostObj = S.estate && S.estate.hosts.find((x) => x.name === host);
    const memPct = pct(g.mem, g.maxmem);
    const cfg = g.config ? Object.keys(g.config).sort() : [];
    replace(box,
      h("h1", {}, g.name || "(unnamed)", " ", h("span", { class: "muted", text: "#" + g.vmid })),
      g.stale ? h("p", { class: "banner warn" }, h("strong", { text: "▲ Stale. " }), "The host or node did not answer, so these values are from an earlier poll" + (hostObj && hostObj.status === "unreachable" && hostObj.error ? " (" + hostObj.error + ")" : "") + ".") : null,
      g.detail_error ? h("p", { class: "banner warn" }, h("strong", { text: "▲ Detail unavailable. " }), g.detail_error + ". The list data below is the latest known.") : null,
      d && d.error && !d.data ? h("p", { class: "banner warn" }, "Could not load the detail view: " + d.error + ". Showing the inventory copy.") : null,
      h("div", { class: "grid" },
        h("section", { class: "card" }, h("h2", { text: "Status" }), kv([
          ["State", [badge(guestBadge(g))]], ["Kind", g.kind], ["Host", link("#/hosts/" + encodeURIComponent(host), host)], ["PVE node", g.node],
          ["Uptime", g.status === "running" ? fmtDuration(g.uptime) : "not running"], ["Template", g.template ? "yes" : "no"],
          ["Tags", g.tags && g.tags.length ? g.tags.join(", ") : "none"]])),
        h("section", { class: "card" }, h("h2", { text: "Resources" }), kv([
          ["CPUs", g.cpus ?? "n/a"],
          ["Memory used", g.mem !== null && g.mem !== undefined ? fmtBytes(g.mem) : "n/a"],
          ["Memory limit", g.maxmem !== null && g.maxmem !== undefined ? fmtBytes(g.maxmem) : "n/a"],
          ["Memory use", memPct === null ? "n/a" : [h("meter", { min: 0, max: 100, value: memPct, "aria-label": "Memory use" }), " " + memPct + "%"]]]))),
      h("section", { class: "card" }, h("h2", { text: "Configuration" }),
        g.config ? h("dl", { class: "kv cfg" }, cfg.flatMap((k) => [h("dt", { class: "mono", text: k }), h("dd", { class: "mono", text: cfgValue(g.config[k]) })]))
          : g.config_restricted ? h("p", { class: "muted", text: "Configuration hidden: Proxmox refuses it to read-only tokens when the container sets environment variables." })
          : h("p", { class: "muted", text: "No configuration was captured for this guest." }),
        g.config_omitted && g.config_omitted.length ? h("div", {}, h("h3", { text: "Withheld on purpose (" + g.config_omitted.length + ")" }),
          h("p", { class: "muted small", text: "These keys can hold secrets and are never sent to the console:" }),
          h("p", { class: "mono", text: g.config_omitted.slice().sort().join(", ") })) : null));
  } };
}
function cfgValue(v) { return typeof v === "string" ? v : JSON.stringify(v); }

function notFoundView() {
  return { title: "Not found", el: h("div", {}, h("h1", { text: "Not found" }), h("p", {}, "That page does not exist. ", link("#/", "Back to the overview"), ".")), update() {} };
}

loadSession();
