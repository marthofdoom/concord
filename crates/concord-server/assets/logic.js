// Pure helpers: no DOM, no network, so `node --test` can exercise them.

// An inventory cycle older than this, while the controller still answers,
// means the poller has stalled; the view must say so instead of looking live.
export const OLD_AFTER_SECS = 90;

export function fmtBytes(n) {
  if (typeof n !== "number" || !isFinite(n)) return "n/a";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? String(n) : n.toFixed(n < 10 ? 2 : 1)) + " " + units[i];
}

export function fmtDuration(secs) {
  if (typeof secs !== "number" || !isFinite(secs) || secs < 0) return "n/a";
  secs = Math.floor(secs);
  const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60), s = secs % 60;
  if (d) return d + "d " + h + "h";
  if (h) return h + "h " + m + "m";
  if (m) return m + "m " + s + "s";
  return s + "s";
}

export function fmtAgo(unixSecs, nowSecs) {
  if (typeof unixSecs !== "number") return "never";
  return fmtDuration(Math.max(0, nowSecs - unixSecs)) + " ago";
}

export function pct(part, whole) {
  if (typeof part !== "number" || typeof whole !== "number" || whole <= 0) return null;
  return Math.min(100, Math.round((part / whole) * 100));
}

// Glyph + word so status never relies on colour alone.
export function hostBadge(host) {
  if (host.status === "unreachable") return { cls: "bad", glyph: "✕", text: "unreachable" };
  if (host.status === "pending") return { cls: "muted", glyph: "○", text: "pending" };
  if ((host.stale_guests ?? staleCount(host)) > 0) return { cls: "warn", glyph: "▲", text: "degraded" };
  return { cls: "ok", glyph: "●", text: "ok" };
}

function staleCount(host) {
  return (host.guests || []).filter((g) => g.stale).length;
}

export function guestBadge(g) {
  if (g.status === "running") return { cls: "ok", glyph: "▶", text: "running" };
  if (g.status === "stopped") return { cls: "muted", glyph: "■", text: "stopped" };
  return { cls: "warn", glyph: "◆", text: String(g.status) };
}

// Flatten the estate into the rows the guests table shows.
export function guestRows(estate) {
  const rows = [];
  for (const h of estate.hosts || []) {
    for (const g of h.guests || []) rows.push({ ...g, host: h.name, host_status: h.status });
  }
  return rows;
}

export function filterGuests(rows, f) {
  const q = (f.q || "").trim().toLowerCase();
  return rows.filter((g) => {
    if (f.host && g.host !== f.host) return false;
    if (f.kind && g.kind !== f.kind) return false;
    if (f.status && g.status !== f.status) return false;
    if (q) {
      const hay = [String(g.vmid), g.name || "", g.host, (g.tags || []).join(" ")].join("\n").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

const SORT_KEYS = ["vmid", "name", "host", "kind", "status", "cpus", "mem", "uptime"];
export function isSortKey(k) { return SORT_KEYS.includes(k); }

export function sortGuests(rows, key, dir) {
  if (!isSortKey(key)) key = "vmid";
  const sign = dir === "desc" ? -1 : 1;
  const val = (g) => (key === "name" ? (g.name || "").toLowerCase() : g[key]);
  return rows.slice().sort((a, b) => {
    const x = val(a), y = val(b);
    // Missing values sort last in both directions: unknown is not zero.
    const xn = x === null || x === undefined, yn = y === null || y === undefined;
    if (xn || yn) return xn === yn ? a.vmid - b.vmid : xn ? 1 : -1;
    const c = typeof x === "number" ? x - y : String(x).localeCompare(String(y));
    return c !== 0 ? sign * c : a.vmid - b.vmid;
  });
}

export function distinct(rows, key) {
  return [...new Set(rows.map((r) => r[key]))].sort();
}

export function countBy(rows, key) {
  const out = {};
  for (const r of rows) out[r[key]] = (out[r[key]] || 0) + 1;
  return out;
}

// Things an operator should look at first, worst first, each with a reason.
export function attention(estate, nowSecs) {
  const items = [];
  for (const h of estate.hosts || []) {
    if (h.status === "unreachable") {
      items.push({ level: "bad", text: `Host ${h.name} is unreachable`, why: h.error || "no reason reported", href: `#/hosts/${encodeURIComponent(h.name)}` });
    } else if (h.status === "pending") {
      items.push({ level: "warn", text: `Host ${h.name} has not been polled yet`, why: "waiting for its first poll", href: `#/hosts/${encodeURIComponent(h.name)}` });
    }
    const stale = (h.guests || []).filter((g) => g.stale).length;
    if (stale > 0 && h.status !== "unreachable") {
      items.push({ level: "warn", text: `${stale} guest${stale === 1 ? "" : "s"} on ${h.name} ${stale === 1 ? "has" : "have"} stale data`, why: "the host or node did not answer; values are from an earlier poll", href: `#/guests?host=${encodeURIComponent(h.name)}` });
    }
    for (const g of h.guests || []) {
      if (g.detail_error) {
        items.push({ level: "warn", text: `Guest ${g.vmid} on ${h.name}: detail unavailable`, why: g.detail_error, href: guestHref(h.name, g.vmid) });
      }
    }
  }
  for (const c of estate.conflicts || []) {
    items.push({ level: "bad", text: `VMID ${c.vmid} exists on more than one host`, why: "on " + c.hosts.join(", ") + "; VMIDs are meant to be unique across the estate", href: `#/guests?q=${c.vmid}` });
  }
  const age = nowSecs - estate.taken_at;
  if (age > OLD_AFTER_SECS) {
    items.push({ level: "bad", text: "Inventory is old", why: `last cycle finished ${fmtDuration(age)} ago`, href: "#/" });
  }
  const rank = { bad: 0, warn: 1 };
  return items.map((it, i) => [it, i]).sort((a, b) => rank[a[0].level] - rank[b[0].level] || a[1] - b[1]).map((p) => p[0]);
}

export function guestHref(host, vmid) {
  return `#/guests/${encodeURIComponent(host)}/${vmid}`;
}

// "#/guests?q=a&sort=name" -> { path: ["guests"], query: {q:"a", sort:"name"} }
export function parseHash(hash) {
  let s = (hash || "").replace(/^#/, "");
  const qi = s.indexOf("?");
  const qs = qi >= 0 ? s.slice(qi + 1) : "";
  if (qi >= 0) s = s.slice(0, qi);
  const path = s.split("/").filter(Boolean).map((p) => { try { return decodeURIComponent(p); } catch { return p; } });
  const query = {};
  for (const [k, v] of new URLSearchParams(qs)) query[k] = v;
  return { path, query };
}

export function buildQuery(query) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) if (v) p.set(k, v);
  const s = p.toString();
  return s ? "?" + s : "";
}

// 'live' | 'old' (controller answers but the cycle is old)
// | 'unreachable' (the last fetch failed). Callers never show a frozen view as live.
export function freshness({ fetchOk, takenAt, nowSecs }) {
  if (!fetchOk) return "unreachable";
  if (typeof takenAt === "number" && nowSecs - takenAt > OLD_AFTER_SECS) return "old";
  return "live";
}
