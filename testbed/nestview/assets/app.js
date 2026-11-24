// nestview UI. Plain DOM, textContent only: every string shown comes from PVE
// or from nestview and is never parsed as HTML.
"use strict";

const POLL_MS = 2500;
const VMIDS = [9001, 9002, 9003];
const ACTIONS = [
  ["start", "start", false],
  ["stop", "stop", true],
  ["reset", "reset", true],
  ["kill", "darken: kill", true],
  ["pause", "darken: pause", true],
  ["sever", "darken: sever", true],
  ["restore", "darken: restore", false],
];

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const k of kids.flat()) {
    if (k == null) continue;
    e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return e;
}

function bytes(n) {
  if (typeof n !== "number") return "?";
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + " " + u[i];
}

function dur(s) {
  if (typeof s !== "number") return "?";
  const d = Math.floor(s / 86400), h = Math.floor(s / 3600) % 24, m = Math.floor(s / 60) % 60;
  return (d ? d + "d " : "") + h + "h " + m + "m";
}

function when(epoch) {
  return typeof epoch === "number" ? new Date(epoch * 1000).toLocaleString() : "";
}

// A Field from the server is {"ok": value} or {"error": "text"}.
function field(f, render) {
  if (f && "error" in f) return el("span", { class: "err" }, f.error);
  return render(f.ok);
}

function row(label, value) {
  return el("tr", {}, el("th", {}, label), el("td", {}, value));
}

function renderStatus(s) {
  const pct = typeof s.cpu === "number" ? (s.cpu * 100).toFixed(1) + "% of " + s.cpus + " vCPU" : "?";
  const power = s.qmpstatus && s.qmpstatus !== s.status ? s.status + " (qmp: " + s.qmpstatus + ")" : s.status;
  return el("table", {},
    row("power", el("span", { class: s.status === "running" && (!s.qmpstatus || s.qmpstatus === "running") ? "ok" : "warn" }, power, s.lock ? " lock=" + s.lock : "")),
    row("uptime", dur(s.uptime)),
    row("cpu", pct),
    row("ram", bytes(s.mem) + " / " + bytes(s.maxmem)),
    row("disk", (s.disk ? bytes(s.disk) : "not reported by PVE for QEMU") + " / " + bytes(s.maxdisk)),
  );
}

function renderConfig(c, ip) {
  return el("table", {},
    row("NIC link", el("span", { class: c.link_down ? "err" : "ok" }, c.link_down ? "DOWN (link_down=1)" : "up")),
    row("net0", el("span", { class: "mono" }, c.net0 ?? "(none)")),
    row("IP", field(ip, (v) => el("span", {},
      el("span", { class: "mono" }, v.addresses.length ? v.addresses.join(", ") : "(none)"),
      el("span", { class: "muted" }, " from " + v.source),
      v.agent_error ? el("div", { class: "muted" }, "agent: " + v.agent_error) : null))),
    row("watchdog", el("span", { class: "mono" }, c.watchdog ?? "(none)")),
    row("agent", el("span", { class: "mono" }, c.agent ?? "(not set)")),
  );
}

function renderSnapshots(list, vmid) {
  if (!Array.isArray(list)) return el("span", { class: "err" }, "unexpected response");
  const real = list.filter((s) => s.name !== "current");
  if (!real.length) return el("span", { class: "muted" }, "no snapshots");
  return el("table", {}, real.map((s) =>
    el("tr", {},
      el("td", { class: "mono" }, s.name),
      el("td", { class: "muted" }, when(s.snaptime), s.parent ? " parent " + s.parent : ""),
      el("td", {}, el("button", { class: "danger", onclick: () => act(vmid, "rollback", s.name) }, "rollback")))));
}

function renderTasks(list) {
  if (!Array.isArray(list)) return el("span", { class: "err" }, "unexpected response");
  if (!list.length) return el("span", { class: "muted" }, "none visible (this token sees only tasks it started)");
  return el("table", {}, list.map((t) => {
    const st = t.status ?? "running";
    return el("tr", {},
      el("td", {}, when(t.starttime)),
      el("td", {}, t.type),
      el("td", { class: st === "OK" ? "ok" : st === "running" ? "warn" : "err" }, st),
      el("td", { class: "mono muted" }, t.upid));
  }));
}

const cards = {};

function card(vmid) {
  if (cards[vmid]) return cards[vmid];
  const data = el("div", {});
  const title = el("h2", {}, String(vmid));
  const snapInput = el("input", { type: "text", placeholder: "snapshot name", maxlength: "40" });
  const controls = el("div", { class: "controls" },
    ACTIONS.map(([a, label, danger]) =>
      el("button", { class: danger ? "danger" : "", onclick: () => act(vmid, a) }, label)),
    snapInput,
    el("button", { onclick: () => act(vmid, "snapshot", snapInput.value.trim()) }, "snapshot"));
  const c = el("section", { class: "card" }, title, data, el("h3", {}, "controls"), controls);
  document.getElementById("vms").append(c);
  return (cards[vmid] = { title, data });
}

function renderVm(v) {
  const c = card(v.vmid);
  const name = v.status && v.status.ok && v.status.ok.name;
  c.title.textContent = v.vmid + " " + (name || v.expected_name);
  c.data.replaceChildren(
    field(v.status, renderStatus),
    field(v.config, (cfg) => renderConfig(cfg, v.ip)),
    el("h3", {}, "snapshots"), field(v.snapshots, (s) => renderSnapshots(s, v.vmid)),
    el("h3", {}, "recent tasks"), field(v.tasks, renderTasks),
  );
}

function renderEstate(e) {
  const body = document.querySelector("#estate .body");
  body.replaceChildren(el("table", {},
    row("SDN zone cnestz", field(e.zone, (z) => el("span", { class: z.status === "available" ? "ok" : "warn" }, z.status ?? JSON.stringify(z)))),
    row("vnet cnest", field(e.vnet, (v) => el("span", { class: "mono" }, "zone " + v.zone + ", type " + v.type))),
    row("storage concord-nest", field(e.storage, (s) => el("span", {},
      bytes(s.used) + " used / " + bytes(s.total) + " (" + bytes(s.avail) + " free)",
      s.active ? "" : el("span", { class: "err" }, " INACTIVE"),
      s.enabled === 0 ? el("span", { class: "err" }, " DISABLED") : ""))),
    row("host guard hook", el("span", { class: "muted" }, e.host_guard)),
  ));
}

async function poll() {
  try {
    const r = await fetch("api/status", { cache: "no-store" });
    if (r.status === 401) { location.href = "login"; return; }
    const j = await r.json();
    if (!r.ok) throw new Error(j.error || r.status);
    renderEstate(j.estate);
    j.vms.forEach(renderVm);
    document.getElementById("fetched").textContent = "polled " + new Date(j.fetched_at).toLocaleTimeString();
  } catch (e) {
    document.getElementById("fetched").textContent = "status unavailable: " + e.message;
  }
}

let busy = false;

async function act(vmid, action, snapname) {
  if (busy) return;
  const dry = document.getElementById("dry-run").checked;
  if ((action === "snapshot" || action === "rollback") && !snapname) {
    alert("enter a snapshot name first");
    return;
  }
  const what = action + (snapname ? " " + snapname : "") + " on VM " + vmid + (dry ? " (DRY RUN)" : " (REAL)");
  const typed = prompt("Confirm " + what + ".\nType the VMID to proceed:");
  if (typed === null) return;
  const body = { confirm_vmid: Number(typed.trim()), dry_run: dry };
  if (snapname) body.snapname = snapname;
  busy = true;
  document.querySelectorAll("button").forEach((b) => (b.disabled = true));
  const out = document.querySelector("#result .body");
  out.textContent = what + ": running...";
  try {
    const r = await fetch("api/vm/" + vmid + "/" + action, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (r.status === 401) { location.href = "login"; return; }
    out.textContent = "HTTP " + r.status + "\n" + JSON.stringify(await r.json(), null, 2);
  } catch (e) {
    out.textContent = what + ": request failed: " + e.message;
  } finally {
    busy = false;
    document.querySelectorAll("button").forEach((b) => (b.disabled = false));
    poll();
  }
}

async function logout() {
  try { await fetch("logout", { method: "POST" }); } finally { location.href = "login"; }
}

document.getElementById("logout").addEventListener("click", logout);
VMIDS.forEach(card);
poll();
setInterval(poll, POLL_MS);
