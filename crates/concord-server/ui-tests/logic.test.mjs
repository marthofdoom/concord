// Run with: node --test crates/concord-server/ui-tests
import test from "node:test";
import assert from "node:assert/strict";
import * as L from "../assets/logic.js";

const g = (vmid, o = {}) => ({ vmid, kind: "qemu", node: "pve1", name: "g" + vmid, status: "running", cpus: 2, mem: 1024, uptime: 5, template: false, tags: [], stale: false, ...o });
const estate = (over = {}) => ({
  cycle: 3, taken_at: 1000, conflicts: [],
  hosts: [
    { name: "pve1", status: "ok", error: null, guests: [g(100), g(101, { status: "stopped", name: null, mem: null })] },
    { name: "pve2", status: "unreachable", error: "connect timeout", guests: [g(200, { stale: true, kind: "lxc" })] },
  ], ...over,
});

test("formatting", () => {
  assert.equal(L.fmtBytes(1536), "1.50 KiB");
  assert.equal(L.fmtBytes(null), "n/a");
  assert.equal(L.fmtDuration(90061), "1d 1h");
  assert.equal(L.fmtDuration(-1), "n/a");
  assert.equal(L.fmtAgo(undefined, 5), "never");
  assert.equal(L.fmtAgo(95, 100), "5s ago");
  assert.equal(L.pct(1, 0), null);
});

test("filter and sort", () => {
  const rows = L.guestRows(estate());
  assert.equal(L.filterGuests(rows, { kind: "lxc" }).length, 1);
  assert.equal(L.filterGuests(rows, { q: "PVE2" }).length, 1);
  assert.equal(L.filterGuests(rows, { host: "pve1", status: "stopped" })[0].vmid, 101);
  assert.deepEqual(L.sortGuests(rows, "vmid", "desc").map((r) => r.vmid), [200, 101, 100]);
  // unknown values sort last in both directions
  assert.equal(L.sortGuests(rows, "mem", "asc").at(-1).vmid, 101);
  assert.equal(L.sortGuests(rows, "mem", "desc").at(-1).vmid, 101);
  assert.equal(L.sortGuests(rows, "bogus", "asc")[0].vmid, 100);
});

test("attention lists worst first with reasons", () => {
  const items = L.attention(estate({ conflicts: [{ vmid: 7, hosts: ["pve1", "pve2"] }] }), 1010);
  assert.equal(items[0].level, "bad");
  assert.ok(items.some((i) => i.why === "connect timeout"));
  assert.ok(items.some((i) => i.text.includes("VMID 7")));
  assert.deepEqual(items.map((i) => i.level), [...items.map((i) => i.level)].sort((a, b) => (a === "bad" ? 0 : 1) - (b === "bad" ? 0 : 1)));
  // stale guests on an unreachable host are explained by the host item, not repeated
  assert.ok(!items.some((i) => i.text.includes("stale data")));
});

test("old inventory is flagged", () => {
  const items = L.attention(estate(), 1000 + L.OLD_AFTER_SECS + 1);
  assert.ok(items.some((i) => i.text === "Inventory is old"));
  assert.equal(L.freshness({ fetchOk: true, takenAt: 1000, nowSecs: 1010 }), "live");
  assert.equal(L.freshness({ fetchOk: true, takenAt: 1000, nowSecs: 5000 }), "old");
  assert.equal(L.freshness({ fetchOk: false, takenAt: 1000, nowSecs: 1001 }), "unreachable");
});

test("badges", () => {
  assert.equal(L.hostBadge({ status: "ok", stale_guests: 1 }).text, "degraded");
  assert.equal(L.hostBadge({ status: "ok", stale_guests: 0 }).text, "ok");
  assert.equal(L.hostBadge({ status: "unreachable" }).text, "unreachable");
  assert.equal(L.guestBadge({ status: "paused" }).text, "paused");
});

test("hash round trip", () => {
  const q = L.buildQuery({ q: "a b", host: "", kind: "lxc" });
  const p = L.parseHash("#/guests" + q);
  assert.deepEqual(p.path, ["guests"]);
  assert.deepEqual(p.query, { q: "a b", kind: "lxc" });
  assert.deepEqual(L.parseHash("#/guests/pve%201/100").path, ["guests", "pve 1", "100"]);
  assert.deepEqual(L.parseHash("").path, []);
});

test("sign-out leaves only on 204 or 401", () => {
  assert.equal(L.signOutOutcome(204), "left");
  assert.equal(L.signOutOutcome(401), "left");
  for (const st of [0, 403, 500, 200]) assert.equal(L.signOutOutcome(st), "failed");
});

test("guest detail failure carries no data", () => {
  assert.equal(L.guestResult(200, { vmid: 1 }).data.vmid, 1);
  const f = L.guestResult(0, null);
  assert.equal(f.data, null);
  assert.match(f.error, /no answer/);
  assert.equal(L.guestResult(404, { error: "no such guest" }).error, "no such guest");
});

test("a 503 after data is never live", () => {
  assert.equal(L.freshness({ fetchOk: true, takenAt: 1000, nowSecs: 1001, waiting: true }), "old");
});
