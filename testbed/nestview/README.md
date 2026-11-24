# nestview

A small dashboard and set of manual test controls for the nested PVE test
estate: VMs 9001-9003 (`nest1`-`nest3`, see `docs/TESTBED.md`). It runs in an
unprivileged LXC, CT 9004, on the estate's host. It is reached only from the
configured client addresses, and every page except the login page needs the
dashboard passphrase.

## What it shows

The page polls nestview every 2.5 s. nestview itself polls PVE every
`refresh_secs` (3 s by default) and caches the result, so the number of open
tabs does not change the load on pveproxy. Every value comes from a PVE
response. If a GET fails, the page shows that error (a 403 included) in place
of the value.

| Item | Source |
|---|---|
| Power, uptime, CPU, RAM, disk | `GET /nodes/<node>/qemu/{vmid}/status/current`. PVE reports `disk` as 0 for QEMU guests, and the page says so. |
| NIC link | `net0` from `GET .../config`: down if it contains `link_down=1` (the same test darken.sh uses) |
| IP | `GET .../agent/network-get-interfaces` if `agent` is enabled and the VM is running. Otherwise `ipconfig0` from the config, labelled as such, with the reason the agent was not used. |
| Watchdog | `watchdog` from the config |
| Snapshots | `GET .../snapshot` |
| Recent tasks | `GET /nodes/<node>/tasks?vmid={vmid}&limit=10`. **The token sees only the tasks it started itself.** PVE shows other users' tasks only to holders of Sys.Audit on `/nodes/<node>` (pve-manager `API2/Tasks.pm`, `check_task_user`), and the nest token does not hold it. Tasks started by build.sh or the GUI therefore do not appear. |
| SDN zone `cnestz` | This node's entry in `GET /nodes/<node>/sdn/zones`. `/cluster/sdn/zones` returns an empty list to this token, because its SDN ACL is on `/sdn/zones/cnestz/cnest` and not on the zone itself (observed). |
| vnet `cnest` | `GET /cluster/sdn/vnets/cnest` |
| Storage `concord-nest` | `GET /nodes/<node>/storage/concord-nest/status` |
| Host guard hook | Always "unknown (not visible to container)". The hook is a file on the host (`/etc/network/if-up.d/concord-nest-guard`). No API call exposes it, and the CT cannot see the host's filesystem. |

## Controls

Each VM card has these controls: start, stop, reset, darken kill / pause / sever /
restore, snapshot (with a name), and rollback (on each snapshot row).

- **Confirm step.** Every control asks you to type the VMID. The POST carries
  it as `confirm_vmid`, and the server refuses the request (HTTP 400) unless
  it equals the VMID in the path.
- **Estate guards before every action.** Every control, power and snapshot
  ones included, first runs darken.sh's guards: `GET /version`, `GET /nodes`
  (one node, the configured one), then `vm_is_ours` (`/cluster/resources`, the config,
  `/pools`). A guest that holds the VMID but is not this estate's `nestN`
  (wrong name, not qemu, untagged, NIC off `cnest`, or outside the pool) is
  refused before any write.
- **Dry run** is a global checkbox, on by default. A dry run returns the exact
  method, path and parameters of each write, and sends no write. It still
  makes the read-only GETs: the five guard reads for every action, and for
  darken modes the state reads `darken.sh --dry-run` makes, because whether a
  write happens, and what sever writes, depends on them.
- **Task outcome.** Every call that returns a UPID is followed with
  `wait_for_task` (1 s polls, up to `task_timeout_secs`). The result shows
  the UPID and its outcome.
- **Audit log.** Every control request, including refused ones (by the
  address, Host, Origin or session checks too), appends JSON lines to
  `audit_log` (default `/var/lib/nestview/audit.jsonl`, mode 0600). Each line
  has `ts, req, client_ip, action, vmid, dry_run, result` and, where they
  apply, `upids, outcome, error, detail`. `dry_run` is `null` when the
  request was refused before its body was read. A control that sends writes
  leaves one row per stage, all with the same `req`:
  - `started`, written before the first write is sent. **If it cannot be
    written, nothing is sent and the request fails with HTTP 500**
    (`result: audit_failed`).
  - `task`, one per UPID, written as soon as PVE returns it. If one cannot be
    written, the sequence stops before its next write.
  - the final row, with the result.
- **A control runs to its end.** It runs in its own task, so closing the tab,
  reloading, or a client Ctrl-C does not cut a darken restore in half. The
  result still reaches the audit log and the journal.
- **One control runs at a time.** A second request gets HTTP 409 until the
  first one has finished, including one whose client has gone away.
- **Errors are not retried.** No call is retried, and a failure is never
  answered with a different or broader call. A 403 is shown as a 403.

### Darken: how it maps to darken.sh

The darken controls mirror `testbed/nested/darken.sh` call for call:

1. `GET /version`
2. `GET /nodes`. **This is the one deviation.** darken.sh's `preflight_common`
   reads `/cluster/status` to check that the endpoint is a standalone host
   with the configured name. That call needs Sys.Audit on `/`, which the nest token does
   not have (observed: HTTP 403 "Permission check failed (/, Sys.Audit)").
   Rather than use a broader token, nestview checks the same two facts from
   `/nodes`: there is exactly one node, and it is the configured one.
3. `vm_is_ours`: `GET /cluster/resources?type=vm` (name `nestN`, type qemu),
   `GET .../config` (tag `concord-nest`, net0 on `bridge=cnest`), and
   `GET /pools?poolid=concord-nest` (membership). lib.sh treats a failed
   config or pool read as "not ours". nestview refuses the same way, but
   includes the error in the message.
4. `GET /cluster/resources?type=vm`, then `GET .../config`, then
   `GET .../status/current`. "Running" below means `status/current`
   `.status` is `running`: the QEMU process exists, so a paused VM counts
   as running. The resources `status` is only logged, because pvestatd
   fills it with `qmpstatus || status` and it reads `paused` for a
   suspended VM (observed on PVE 9.2.21).
   The states darken acts on are the same as darken.sh's: `stopped` (any
   qmp), or `running` with qmp `running`, `paused`, `suspended` or
   `prelaunch`. `prelaunch` counts as paused, as PVE's `vm_is_paused` does.
   Every other state refuses the action before any write and names the
   state: a live process in `io-error`, `internal-error`, `guest-panicked`,
   `shutdown` or an unknown qmp state is a fault to look at by hand, and a
   `.status` outside its schema's running|stopped enum is refused as well.
5. One of the following, depending on the mode:
   - kill: refused unless running (paused, suspended and prelaunch included); otherwise `POST status/stop` and wait.
   - pause: refused unless qmp=running; otherwise `POST status/suspend` and wait.
   - sever: `PUT config net0=<net0>,link_down=1`, in every accepted state. This call is synchronous,
     so there is no task to wait for. It is refused if the NIC is already
     severed. If the VM is stopped, the setting is saved and applies at next
     start, and the log says so.
   - restore: three steps, in this order. `POST status/start` and wait, if
     the VM is stopped. `POST status/resume` and wait, if the VM is running
     and qmp is paused, suspended or prelaunch (such a VM gets only this,
     never a start). `PUT config` with every `,link_down=1` removed, if
     severed. The log says "nothing to restore" only when qmp is running
     and the NIC is linked.

darken.sh's `wait_task` treats any exit status other than `OK` as fatal. So
does nestview: a `WARNINGS: n` result stops a restore sequence, and the
result reads `warnings`.

## Security model

**Install and keep host-guard active on the host before deploying nestview.**
The deploy below makes it a precondition. The
reason: nestview cannot tell the operator from a nested node by
address. Traffic from `cnest` (the nested nodes, and any guest inside them)
leaves the host SNATed as the host's own address, and so does any other guest
NATed through it. Without host-guard's raw-table drops, a nested node could
reach the CT's port 8099 looking like the host. The passphrase still stands
between it and the controls, but the address check and nftables would not if
the operator's address is the host's.

- **Token.** nestview uses only `concord@pve!nest`, the pool-scoped token
  that build.sh creates. The token file holds one line,
  `concord@pve!nest=<secret>`, as build.sh writes it. nestview refuses any
  other token id. It reads the token only from `$CREDENTIALS_DIRECTORY/token`
  (systemd `LoadCredential=`), never from argv or the environment. It never
  appears in the UI, the logs, the audit log or any error.
- **TLS** is pinned by SHA-256 fingerprint (concord-pve), and verification
  cannot be turned off. The fingerprint is `GET /nodes` `ssl_fingerprint`;
  check it against the certificate on the wire.
  If the host certificate is renewed, update the config.
- **VMID allowlist.** The nest token holds PVEVMAdmin on the whole pool,
  whatever is put in it. The token's ACLs are therefore not the boundary.
  The `Vmid` type is: it can only be 9001, 9002 or 9003.
  Every guest path is built from it, and a request for any other VMID gets
  HTTP 403 before any PVE call. There is no generic proxy route.
- **Login.** Every route except the login page (`/login`, and the
  stylesheet it links) needs a session, the status API included. Without
  one, `/` redirects to `/login` and every other route answers 401.
  - The passphrase lives in a root-owned 0600 file, `/etc/nestview/passphrase`,
    handed to the service by systemd `LoadCredential=`. nestview keeps only
    its SHA-256, compares digests in constant time, and never logs it or puts
    it in an error.
  - A correct login sets `nestview_session`: 32 random bytes, `HttpOnly`,
    `SameSite=Strict`, `Path=/`, valid for `session_ttl_secs` (8 h by
    default). Sessions are kept server-side, in memory. A restart or
    "log out" ends them.
  - After 5 failed logins in 60 s, every login is refused with 429 for the
    rest of the window, the right passphrase included. The limit is global
    rather than per address, because clients may all arrive from the host's address.
- **Clients.** nftables in the CT accepts 8099 and 22 only from
  the operator address set in `nftables.conf`. nestview also refuses (403) any peer not in
  `allowed_clients`. These stay as defence in depth. As said above, an
  address that is the host's means "anything the host NATs", not "the operator".
- **Host and Origin.** Every request's `Host` must be one of `allowed_hosts`,
  or it gets 403. That stops DNS rebinding: a hostile page that rebinds its
  own name to the CT's address is same-origin with itself, but its requests
  still carry its own Host. Every POST must also carry an `Origin` of
  `http://` plus an allowed host (`null` is refused), and is refused if
  `Sec-Fetch-Site` is present and not `same-origin`.
- **Referrer-Policy is `same-origin`, not `no-referrer`.** A form submission
  is a navigation, and for those browsers apply the page's referrer policy to
  the `Origin` header as well. Under `no-referrer` the login form would post
  `Origin: null`, and login would always be refused. `same-origin` still
  sends no referrer to any other origin. A test pins it.
- **CSRF.** On top of the Origin check and the SameSite cookie, controls
  accept `application/json` bodies only, and nothing answers a CORS
  preflight. The dashboard is served with a strict CSP (`script-src 'self'`,
  `form-action 'none'`) and `frame-ancestors 'none'`. The login page has no
  script at all, and allows only a same-origin form action.
- **Credentials and the service user.** Neither secret file is readable or
  writable by the `nestview` user. systemd copies them into
  `$CREDENTIALS_DIRECTORY` for the service alone: mode 0400 plus an ACL entry
  granting the service user read. On tmpfs, where `/run/credentials` lives,
  that stats as 0440, because with an ACL the group bits show the ACL mask
  (`group::---`, `mask::r--`). nestview therefore refuses a credential only if
  it is writable by anyone or readable by others.
- **CT 9004 is in no pool.** The nest token's PVEVMAdmin on pool
  `concord-nest` therefore gives it no rights at all over the container
  that stores the token.

## Config

`/etc/nestview/config.json` (see `deploy/config.example.json`):

| Key | Default | |
|---|---|---|
| `bind` | `0.0.0.0:8099` | listen address |
| `pve_url` | required | `https://HOST:8006` |
| `fingerprint` | required | SHA-256 of the host's certificate |
| `node` | required | PVE node name |
| `allowed_hosts` | required | `Host` values the UI is opened by, e.g. `["192.0.2.77:8099"]` |
| `audit_log` | `/var/lib/nestview/audit.jsonl` | |
| `allowed_clients` | required | client addresses the UI answers |
| `refresh_secs` | 3 | status poll interval towards PVE |
| `task_timeout_secs` | 300 | how long to wait on a task before reporting "still running" |
| `session_ttl_secs` | 28800 | login session lifetime, 60 s to 7 days |

Nothing site-specific has a default. The example's placeholders (`PVE_HOST`,
`PVE_CERT_SHA256`, `NODE_NAME`, `CT_IP`, `OPERATOR_IP`) are refused: an unedited
config does not start.

There is no key for either secret. The token and the passphrase come only
from `$CREDENTIALS_DIRECTORY/token` and `$CREDENTIALS_DIRECTORY/passphrase`,
which systemd fills from the unit's `LoadCredential=` lines.

If the status poller ever stops, nestview exits non-zero, and the unit's
`Restart=on-failure` starts it again, so `/api/status` never serves a stale
snapshot indefinitely.

## Build

The binary must run on Debian 13 (glibc 2.41). Build natively for
`x86_64-unknown-linux-gnu` on a system no newer than that, and check the symbols
before installing:

```
cargo build -p nestview --release --locked
objdump -T target/release/nestview | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1   # must be <= GLIBC_2.41
```

If you build somewhere with a newer glibc and the check fails, build inside
the CT instead (rustup there). The other route is
`rustup target add x86_64-unknown-linux-musl` plus musl-tools, building with
`--target x86_64-unknown-linux-musl`.

## Deploy (operator on the host, with the admin API token and SSH)

The sequence uses only the PVE API (through `testbed/nested/pve.sh`, which takes
the path as its **last** argument) and SSH into the CT. It needs no `pct` and no
root shell on the host, except for the one host-guard check in step 0. Every
site value comes from `testbed/site.env` (see `docs/TESTBED.md`).

Run it in a `bash` started for the purpose, not your login shell: the
`|| exit 1` guards end that shell when a step fails, and the reason stays on
the terminal above the parent prompt.

```bash
# Run from the repo root. Loads and checks testbed/site.env; stops this shell if it is not filled in.
. testbed/nested/site.sh && site_load_estate
P=$PWD/testbed/nested/pve.sh
SEC=$SECRETS_DIR
OPERATOR_IP=$HOST_LAN_IP                       # the address your browser connects from
TEMPLATE=                                      # volid of a Debian 13 LXC template, e.g. local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst
[[ -n $TEMPLATE ]] || { echo "set TEMPLATE first" >&2; exit 1; }
# pve.sh runs curl without -f, so a refused POST still exits 0 and its
# .data is null. upid_of turns that into a failure that shows PVE's own error.
# Printing a raw response is safe: pve.sh sends the token only in a request
# header, built from the file, and never echoes it; PVE does not echo it back.
upid_of() {  # print the UPID in a POST response, or print the response and fail
  local u; u=$(jq -r '.data // empty' <<<"$1" 2>/dev/null)
  [[ $u == UPID:* ]] || { echo "no UPID (request refused?): ${1:-<empty response>}" >&2; return 1; }
  printf '%s\n' "$u"
}
wait_upid() {  # poll a task until it stops, 10 min at most; print its exit status (expect OK)
  [[ $1 == UPID:* ]] || { echo "not a UPID: ${1:-<empty>}" >&2; return 1; }
  local enc s i; enc=$(jq -rn --arg u "$1" '$u|@uri')
  for ((i = 0; i < 300; i++)); do
    s=$($P "/nodes/$NODE/tasks/$enc/status")
    if [[ $(jq -r '.data.status // empty' <<<"$s" 2>/dev/null) == stopped ]]; then
      jq -r .data.exitstatus <<<"$s"
      [[ $(jq -r .data.exitstatus <<<"$s") == OK ]]
      return
    fi
    sleep 2
  done
  echo "task $1 not stopped after 600 s; last status response: $s" >&2; return 1
}

# 0. Preconditions.
#    - Release build plus the GLIBC check (see "Build"). Run from the repo root.
#    - host-guard is installed and active. Either of these is evidence:
#      a) as root on the host:
#           iptables -w 10 -t raw -S PREROUTING | grep -- '-i cnest -d 192.168.0.0/16 -j DROP'
#         No output means stop here.
#      b) a functional probe from nest1 (no root needed; same SSH as step 9):
#         the host's LAN address:8006 and other LAN addresses time out,
#         while the internet is reachable. Any answer from those
#         means stop here.
#    - Storage concord-nest has 'rootdir' (build.sh sets it on a new one), so
#      the CT's rootfs sits with the rest of the test estate:
$P -X PUT --data-urlencode content=images,iso,import,rootdir /storage/concord-nest
$P /storage/concord-nest | jq -r .data.content          # expect rootdir listed

# 1. Deploy key, kept in the secret store (private key 0600).
ssh-keygen -t ed25519 -N '' -C nestview-deploy -f "$SEC/nestview-deploy_ed25519"

# 2. Dashboard passphrase: 32 random bytes, base64, no trailing newline.
#    Never printed. Open the file yourself to log in the first time, and let
#    the browser's password manager keep it.
( umask 077 && head -c 32 /dev/urandom | base64 -w0 > "$SEC/nestview-passphrase.txt" )
stat -c '%a %s' "$SEC/nestview-passphrase.txt"           # expect "600 44"

# 3. Create CT 9004: unprivileged, nesting, in NO pool, rootfs on concord-nest.
#    The description's first line is the marker teardown.sh checks; keep it
#    exactly. The address and ports go into the notes in step 4, once DHCP has
#    given the CT its address.
r=$($P -X POST \
  --data-urlencode vmid=9004 \
  --data-urlencode "ostemplate=$TEMPLATE" \
  --data-urlencode hostname=nestview \
  --data-urlencode unprivileged=1 \
  --data-urlencode features=nesting=1 \
  --data-urlencode cores=1 --data-urlencode memory=256 --data-urlencode swap=128 \
  --data-urlencode rootfs=concord-nest:4 \
  --data-urlencode net0=name=eth0,bridge=vmbr0,ip=dhcp \
  --data-urlencode onboot=1 --data-urlencode ostype=debian \
  --data-urlencode "description=nestview (CON-51): dashboard for the CON-48 nested estate" \
  --data-urlencode "ssh-public-keys@$SEC/nestview-deploy_ed25519.pub" \
  /nodes/$NODE/lxc)
upid=$(upid_of "$r") || exit 1
wait_upid "$upid" || exit 1                              # expect OK
$P '/pools?poolid=concord-nest' | jq -c '[.data[0].members[].vmid // empty]'   # expect [9001,9002,9003], no 9004

# 4. Start it and find its address (and MAC, for a DHCP reservation).
r=$($P -X POST /nodes/$NODE/lxc/9004/status/start)
upid=$(upid_of "$r") || exit 1
wait_upid "$upid" || exit 1                              # expect OK
$P /nodes/$NODE/lxc/9004/config | jq -r '.data.net0, .data.features, .data.rootfs'
#    DHCP may not have answered yet right after start: retry for up to 60 s,
#    and stop if there is still no address (an empty CT_IP would put ":8099"
#    into allowed_hosts in step 6).
for i in $(seq 30); do
  CT_IP=$($P /nodes/$NODE/lxc/9004/interfaces | jq -r '.data[]|select(.name=="eth0").inet // empty' | cut -d/ -f1)
  [[ -n $CT_IP ]] && break; sleep 2
done
[[ -n $CT_IP ]] || { echo "CT 9004 has no eth0 address yet; check DHCP, then rerun step 4" >&2; exit 1; }
echo "CT_IP=$CT_IP"
#    Notes: the marker line, then the addresses and ports. Reserve CT_MAC ->
#    CT_IP on your DHCP server, or the address can change.
CT_MAC=$($P /nodes/$NODE/lxc/9004/config | jq -r '.data.net0' | sed -n 's/.*hwaddr=\([^,]*\).*/\1/p')
NOTES=$(cat <<EOF
nestview (CON-51): dashboard for the CON-48 nested estate

**Addresses** (vmbr0, LAN)
- IP: \`$CT_IP\` (DHCP, MAC $CT_MAC)
- Dashboard: http://$CT_IP:8099/ (passphrase login)
- SSH: \`root@$CT_IP\` port 22, deploy key nestview-deploy_ed25519 only
- In-CT nftables: 8099 and 22 accepted only from $OPERATOR_IP

Docs: concord testbed/nestview/README.md
EOF
)
$P -X PUT --data-urlencode "description=$NOTES" /nodes/$NODE/lxc/9004/config | jq -c .
$P /nodes/$NODE/lxc/9004/config | jq -r '.data.description | split("\n")[0]'   # expect the marker line
# The CT's host key is trust-on-first-use; it is pinned in its own known_hosts.
SSHO=(-i "$SEC/nestview-deploy_ed25519" -o UserKnownHostsFile="$SEC/nestview_known_hosts" -o StrictHostKeyChecking=accept-new)
S() { ssh "${SSHO[@]}" "root@$CT_IP" "$@"; }
C() { scp "${SSHO[@]}" "$@"; }

# 5. Firewall first, so the UI is never reachable without it. The SSH session
#    survives: it is established, and tcp/22 from OPERATOR_IP is allowed
#    (run this from that address).
S 'apt-get update && apt-get install -y nftables'
sed "s/^define operator = OPERATOR_IP$/define operator = $OPERATOR_IP/" testbed/nestview/deploy/nftables.conf \
  | S 'cat > /etc/nftables.conf'
#    The Debian template ships nftables enabled and already running its default
#    accept-all ruleset, so `enable --now` would not reload it: restart instead.
S 'chmod 0644 /etc/nftables.conf && nft -c -f /etc/nftables.conf && systemctl enable nftables && systemctl restart nftables && nft list ruleset'

# 6. Service user, directories, binary, config (allowed_hosts set to this CT),
#    docs and unit.
S 'useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin nestview &&
   install -d -m 0750 -o root -g nestview /etc/nestview && install -d /usr/local/share/doc/nestview'
C target/release/nestview "root@$CT_IP:/usr/local/bin/nestview"
sed -e "s|https://PVE_HOST:8006|https://$PVE_API|" -e "s/PVE_CERT_SHA256/$PVE_FINGERPRINT/" \
    -e "s/NODE_NAME/$NODE/" -e "s/CT_IP/$CT_IP/" -e "s/OPERATOR_IP/$OPERATOR_IP/" testbed/nestview/deploy/config.example.json \
  | S 'cat > /etc/nestview/config.json'
C testbed/nestview/README.md "root@$CT_IP:/usr/local/share/doc/nestview/README.md"
C testbed/nestview/deploy/nestview.service "root@$CT_IP:/etc/systemd/system/nestview.service"
S 'chmod 0755 /usr/local/bin/nestview &&
   chown root:nestview /etc/nestview/config.json && chmod 0640 /etc/nestview/config.json &&
   chmod 0644 /usr/local/share/doc/nestview/README.md /etc/systemd/system/nestview.service'
#    The CT has no jq; grep for the exact entry instead.
S "grep -F '\"$CT_IP:8099\"' /etc/nestview/config.json"   # expect the allowed_hosts line

# 7. Secrets: over stdin, never on argv or the screen. root:root 0600; the
#    service gets them through LoadCredential=.
for f in token:concord-nest-token.txt passphrase:nestview-passphrase.txt; do
  S "umask 077 && cat > /etc/nestview/${f%%:*} && chown root:root /etc/nestview/${f%%:*} &&
     chmod 0600 /etc/nestview/${f%%:*} && stat -c '%n %a %U' /etc/nestview/${f%%:*}" \
    < "$SEC/${f#*:}"                                     # expect "... 600 root"
done

# 8. Start.
S 'systemctl daemon-reload && systemctl enable --now nestview && systemctl status nestview --no-pager && journalctl -u nestview -n 20 --no-pager'
#    Success: the service is active and the journal shows "nestview listening".
#    status=226/NAMESPACE: the sandboxing needs nesting; check features in step 4's GET config.
#    status=243/CREDENTIALS: a LoadCredential= source file is missing (step 7).
#    "token file ... has mode ...": the delivered credential is writable or
#    other-readable; 0400 and 0440 are both accepted (see "Credentials").

# 9. Verify, from the host.
U="http://$CT_IP:8099"
curl -s -o /dev/null -w '%{http_code}\n' "$U/api/status"                  # expect 401
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: evil.example' "$U/"    # expect 403
#    Log in without putting the passphrase on argv: curl reads it from the file.
JAR=$(mktemp)
curl -s -o /dev/null -w '%{http_code}\n' -c "$JAR" -H "Origin: $U" \
  --data-urlencode "passphrase@$SEC/nestview-passphrase.txt" "$U/login"    # expect 303
curl -s -b "$JAR" "$U/api/status" | jq '.estate'                          # works
curl -s -o /dev/null -w '%{http_code}\n' -b "$JAR" -H "Origin: $U" -X POST "$U/logout"   # expect 204
rm -f "$JAR"
#    Negative check (host-guard): from nest1, the CT must be unreachable.
#    With -w, curl prints 000 when no response came; it then exits 28 on a
#    timeout (host-guard's DROP), or 7 if a REJECT refused the connection.
ssh -i "$SEC/concord-nest_ed25519" -o UserKnownHostsFile="$SEC/concord-nest_known_hosts" \
  debian@10.99.0.11 "curl -s --max-time 5 -o /dev/null -w '%{http_code}\n' http://$CT_IP:8099/login; echo exit=\$?"
#    expect: "000" then "exit=28" (or exit=7). Any code other than 000 means
#    host-guard is not active: stop nestview (S 'systemctl stop nestview')
#    until it is.
S 'nft list counter inet nestview dropped_in'
```

Open `http://<CT_IP>:8099/` in a browser at the operator address and log in with the
passphrase. A DHCP reservation for the CT's MAC keeps that URL, and so
`allowed_hosts`, stable. If the address changes, update `allowed_hosts` and
restart the service.

`LoadCredential=` needs systemd to set up `/run/credentials/nestview.service`.
In an unprivileged CT where it cannot mount there, systemd 254 and later
(Debian 13 ships 257) fall back to a plain directory readable only by the
service. Check the journal at step 8.

## Tests

`cargo test -p nestview` covers:

- the allowlist: every VMID 0-20000 plus spellings such as `09001`, all
  through the real router, and none reaching PVE;
- login: unauthenticated requests refused on every route, a working login
  with an HttpOnly SameSite=Strict cookie, a wrong passphrase refused, the
  failed-login limit (also under 64 concurrent wrong logins), expiry and
  logout;
- the login form as a browser submits it: the Origin is derived from the
  Referrer-Policy the login page is served with, per the Fetch standard, and
  that policy is pinned to `same-origin`;
- the credential mode rule: 0400 and 0440 (systemd's ACL) accepted, any
  write or "other" bit refused;
- that the passphrase is absent from Debug output, responses, the audit log
  and the loader's errors;
- Host, Origin and `Sec-Fetch-Site` refusals, and audited guard refusals;
- `confirm_vmid` mismatches and non-JSON bodies (`dry_run: null` in the row);
- the estate guards before every action, power and snapshot ones included;
- dry runs sending no write (MockPve);
- each darken mode's exact call sequence and parameters against MockPve;
- the audit trail: `started` before the first write, `task` per UPID, the
  final row, each row synced to disk, and a failed audit write that stops the
  action (HTTP 500);
- a panic inside a control: a final `error` row with the same `req`, the
  poller kicked, and the lock released only after that row;
- a client that disconnects while a restore waits on its task: the restore
  still finishes, holds the lock until then, and is recorded;
- that a paused VM's guest agent is not queried;
- that a 403 is surfaced once and not retried;
- that the token is absent from the Debug output and errors of the config,
  the token loader and the real HTTP client.
