# concord-pve: assumptions and what was observed

The "Observed" and "Captured" sections below record what real hosts
answered. The rest is behaviour the client relies on that was read from Proxmox
source or docs; where a capture settled an item it is marked **Settled**.

Tests no longer hand-write response bodies: they load the sanitised sets in
`tests/fixtures/pve-<version>/` (see "Fixtures" below).

## Fixtures

`tests/fixtures/pve-<version>/` holds one capture per PVE version, each with a
`MANIFEST.json` (version, endpoint to file mapping; no host, no date).
Current sets: 9.2.11, 9.2.21 and 9.2.28. Failures are in `errors/`, as
`{status, message, errors}`. Bodies are the unwrapped `data`, pretty-printed
with sorted keys so a re-capture diffs cleanly.

Re-capture (read-only; GET only, by construction, see `ReadOnly`):

```text
cargo run -p concord-pve --example capture -- \
    --host HOST[:8006] --token-file FILE --fingerprint AA:BB:... \
    --out crates/concord-pve/tests/fixtures
```

`FILE` holds `USER@REALM!TOKENID=SECRET` on one line; give it a `PVEAuditor`
token. Get the fingerprint from the live certificate:
`openssl s_client -connect HOST:8006 </dev/null | openssl x509 -noout -fingerprint -sha256`.
The tool sanitises before writing and refuses to write anything `LeakScanner`
still flags. Generic patterns are built in; for your own names, set
`CONCORD_ESTATE_DIGESTS` to a private file with one SHA-256 of a lowercase name
per line (`printf %s name | sha256sum`). Never commit that file: digests of short
names are trivially reversed.

It also replaces the values that describe a host rather than PVE (`src/normalise.rs`), so nothing
below about a *number* is an observation of a real one: guest ids become 101 up (9101 up for guests
with no endpoints of their own; the documented test estate's 9001-9004 stay), dates count hours from
2026-01-01 UTC in their original order, and sizes, counters, uptimes, CPU details, pids and UPID fields
are constants. Zero stays zero, types and numbers-as-strings stay, and fields that repeat a fact still
agree. Long lists keep one entry per shape, plus the guests captured in their own right. A failed
task's reason is generic text, and certificate tasks are listed as `aptupdate`.

After a capture, read the diff: the sanitiser keys on field names it
knows, so a new free-text field in a newer PVE is the thing to look for.

The sanitiser (`src/sanitize.rs`) keeps field names, types, enums and number
formats, and replaces: node, guest, storage, pool, tag, user and token names
(`node1`, `guest-<vmid>`, `storage1`, `user1@pam`, ...), IPs (RFC 5737 ranges),
MACs (`02:00:00:..`), UUIDs (`00000000-0000-4000-8000-..`), fingerprints,
digests, descriptions and notes, SSH keys, storage paths, host paths of bind
mounts, user-named volume files, and domain names in free text. One consequence:
a pool and a storage that share a real name share a placeholder too, and a
token-owned UPID user is `user1@pam!token-1` while the separate `user` field of
the same task still reads `root@pam`. Two further deliberate non-captures:
a running task (it is gone before it can be read; the poller tests derive the
running body from a real stopped one) and the full `apt/update` package list.

Verified from source/docs (read, not observed):
- Auth header `PVEAPIToken=USER@REALM!TOKENID=SECRET` (pve.proxmox.com/wiki/Proxmox_VE_API).
- POST/PUT accept `application/x-www-form-urlencoded` (same page; pve-http-server `AnyEvent.pm`).
- `/api2/json` body is `{"data": ...}`; on error status the formatter adds `message`
  and, if non-empty, `errors` (pve-http-server `Formatter/Standard.pm`).
- The `extjs` format reports failure as `success: 0` inside HTTP 200; `/api2/json` does not.
- UPID grammar `UPID:node:pid(8hex):pstart(8-9hex):starttime(8hex):type:id:user:`
  (pve-common `PVE/UPID.pm`); `exitstatus` is `OK`, `WARNINGS: n`, or an error
  message (`read_status`, `status_is_error`).
- Task status fields `status` (running|stopped), `exitstatus` (pve-manager `API2/Tasks.pm`).
- `/version` returns `version`, `release`, `repoid`; `/nodes` items per `API2/Nodes.pm`.

Observed on a live standalone host (PVE 9.2.21; unauthenticated
requests only, no credentials sent):
- **401 has an empty body.** `GET /api2/json/nodes` without auth answers
  `HTTP/1.1 401 No ticket` with no body; the text is only in the reason phrase. The
  client falls back to the reason phrase (hyper's `ReasonPhrase`, present only when it
  differs from the canonical one), then to the canonical phrase.
- **400 body shape.** `POST /api2/json/access/ticket` without parameters answers
  `HTTP/1.1 400 Parameter verification failed.` with
  `{"message":"Parameter verification failed.\n","data":null,"errors":{"password":"property is missing and it is not optional","username":"property is missing and it is not optional"}}`.

Assumptions:
- **Failures inside a 200 body.** The task text says PVE does this. From source it
  only happens for the `extjs`/`htmljs` formats, never `/api2/json`. The client still
  rejects a 2xx body with `success` of `0`/`false`, defensively. To confirm: no
  `/api2/json` endpoint returns 200 with a failure shape (e.g. a task-starting call
  whose `data` is an error string). **Settled for reads:** none of the 76 GETs captured
  returned one; write endpoints were not exercised (capture is GET-only).
- **Error `message` text.** The client reads `message` from the JSON body, else a
  non-JSON body as text, else the reason phrase (400 and 401 now observed, above).
  **Settled:** captured 400, 403, 500 and 501 (see below). Not 404; PVE answers a
  missing guest with 500. The 500 is JSON, not plain text.
- **`errors` shape.** An object of parameter name to message (observed on the 400
  above). Carried through as opaque JSON, so a different shape is not a failure, only
  less pretty.
- **Percent-encoded UPID in the path.** pveproxy is assumed to decode `%3A` and `%40`
  in path segments. **Settled:** real task statuses were fetched through `api_path`'s encoding on three hosts (a test pins the fixture path to `api_path` output).
- **`/nodes` for an offline node** omits `uptime`/`ssl_fingerprint`; they are `Option`.
- **A stopped task always has `exitstatus`.** Source caches/reads it on every stopped
  status call; if absent the poller reports `Failed`, not success.
- **Leaf certificate parseable by webpki.** Signature verification parses the PVE
  leaf with rustls-webpki. **Settled:** the pinned client completed the handshake against the three hosts' real certificates. Not distinguished: which of them is PVE-CA-signed and which self-signed.
- **Fingerprint input.** PVE shows SHA-256 of the leaf DER as colon-separated upper
  hex (`pvenode cert info`, `/nodes` `ssl_fingerprint`); assumed to be the same DER the
  server sends as end-entity. **Settled:** the pin taken from `openssl s_client` equalled `/nodes` `ssl_fingerprint` and connected.
- **TLS versions.** rustls safe defaults (TLS 1.2 and 1.3). PVE hosts old enough to
  offer only TLS 1.0/1.1 will fail to connect.
- **HTTP/1.1 only.** pveproxy is assumed to speak HTTP/1.1; http2 is not enabled. **Settled:** all captures worked over HTTP/1.1.

Captured (PVE 9.2.11, 9.2.21, 9.2.28):
- **500 for a missing guest, as JSON.** `GET /nodes/{n}/qemu/{unknown}/status/current`
  answers `500` with `{"message":"Configuration file 'nodes/{n}/qemu-server/{id}.conf' does not exist\n","data":null}`;
  the reason phrase carries the same text. Not 404.
- **501 for an unknown path:** `{"data":null,"message":"Method 'GET /nodes/{n}/nonexistent' not implemented"}`, no `errors`.
- **400 with `errors` for a task that does not exist:** status of an unknown UPID answers
  `400`, message `Parameter verification failed.\n`, `errors: {"upid": "no such task"}`.
  (So "no such task" is a 400, not a 404, and arrives in `errors`, not `message`.)
- **403:** `Permission check failed (/nodes/{n}, Sys.Modify)\n`, no `errors`.
- **Error messages end in `\n`** (400, 403, 500); the 501 does not. The client keeps the text verbatim.
- **`GET /nodes/{n}/tasks` answers `{"data":[...],"total":N}`.** `total` is a sibling of
  `data`; `parse_envelope` returns only `data`, so a caller wanting the count of tasks
  cannot get it today. Task list items carry `status` only once finished and there it
  holds the outcome text (`OK`, or the error message), where task *status* uses
  `status: stopped` plus `exitstatus`. List items also carry a separate `tokenid`.
- **Task status real shape:** `exitstatus, id, node, pid, pstart, starttime, status, type, upid, user`.
  `id` is `""` for subjectless tasks and may be free text (a domain for ACME). `user` is the
  bare `user@realm`; the token appears only in the UPID and in the list's `tokenid`.
  A failed task's `exitstatus` is the error text, as `classify` assumes.
- **UPIDs** are uppercase hex, 8-digit `pid`, `pstart` and `starttime`, and round-trip
  through `Upid` byte for byte, including the empty-subject form (`...:aptupdate::root@pam:`).
- **`/nodes` on a standalone host** carries `ssl_fingerprint` and `uptime` as well as
  `cpu, disk, id (node/<name>), level (""), maxcpu, maxdisk, maxmem, mem, node, status, type`.
- **`/cluster/resources?type=vm` works on a standalone host** (not in a cluster) and lists
  qemu and lxc guests with `id` as `<type>/<vmid>`.
- **Numbers and strings are mixed by endpoint.** QEMU config gives `memory` and `agent` as
  *strings* (`"3072"`, `"1"`) while `status/current` gives `agent: 1` as a number and LXC
  config gives `memory: 3072` as a number. Disk and network fields are `key=value,...`
  strings. Any typed config model must parse, not just deserialize.
- **Snapshot lists** end with a pseudo-entry named `current` (with `parent` when real
  snapshots exist, and `running`); a guest with no snapshots lists just that.
- **Pools:** `/pools` lists `{poolid, comment}`; `/pools/{id}` adds `members` holding full
  resource objects (so a guest's pool is not on the guest).
- **A fresh node has empty `/pools`, `/nodes/{n}/qemu` and `/lxc`** (`[]`), which is a shape
  too; the 9.2.28 set is exactly that.
