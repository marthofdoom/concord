#!/usr/bin/env bash
# Host-side guard for the nested estate. Needs root. Self-contained: it reads no config and sources nothing.
#
#   sudo host-guard.sh install    write /etc/network/if-up.d/concord-nest-guard and apply the rules now if cnest is up
#   sudo host-guard.sh remove     delete the hook and loop-delete the rules
#   host-guard.sh status          hook present? rules present? (rule check needs root)
#
# Why: the nodes are bridged onto vnet cnest, which the host routes and SNATs. Without a host-side
# guard a node, or a guest inside it, can reach the whole LAN (as the host's own address), any overlay
# network the host is on (tailnet), and the host's own services (sshd, pveproxy). The in-node nftables only protect against mistakes.
#
# How: an ifupdown hook that does nothing unless IFACE=cnest. It never edits vmbr0 or
# /etc/network/interfaces. The rules are in the raw table (before conntrack, and tailscaled cannot
# reach that table, so it cannot undo them) plus an INPUT rule. Every insert is preceded by a
# check, so ifreload re-running the hook does not stack duplicates. Remove deletes in a loop.
#
# Rules (cnest is the only interface they match):
#   raw PREROUTING  drop traffic from cnest to 192.168/16, 172.16/12, 100.64/10 (CGNAT, used by Tailscale), 169.254/16
#   raw PREROUTING  drop traffic from cnest to 10/8 except 10.99.0.0-10.99.0.255
#   INPUT           reject NEW non-ICMP connections from cnest to the host (replies to the host's own ssh still work)
#   ip6tables INPUT drop everything from cnest (the bridge has a fe80 address; sshd and pveproxy listen on it)
set -euo pipefail

HOOK=/etc/network/if-up.d/concord-nest-guard
# Identity marker: install and remove act only on a hook that contains it.
MARK='# concord-nest-guard (CON-48)'

# -w 10: legacy iptables exits at once when the xtables lock is held (tailscaled, boot), which would
# leave the guard silently absent. %A is replaced by -C (check), -I (insert) or -D (delete).
RULES=(
    "iptables -w 10 -t raw %A PREROUTING -i cnest -d 192.168.0.0/16 -j DROP"
    "iptables -w 10 -t raw %A PREROUTING -i cnest -d 172.16.0.0/12 -j DROP"
    "iptables -w 10 -t raw %A PREROUTING -i cnest -d 100.64.0.0/10 -j DROP"
    "iptables -w 10 -t raw %A PREROUTING -i cnest -d 169.254.0.0/16 -j DROP"
    "iptables -w 10 -t raw %A PREROUTING -i cnest -d 10.0.0.0/8 -m iprange ! --dst-range 10.99.0.0-10.99.0.255 -j DROP"
    "iptables -w 10 %A INPUT -i cnest -m conntrack --ctstate NEW ! -p icmp -j REJECT"
    "ip6tables -w 10 %A INPUT -i cnest -j DROP"
)

need_root() { [[ $EUID -eq 0 ]] || { echo "host-guard.sh $1 must run as root (sudo /var/lib/concord-nest/bin/host-guard.sh $1)" >&2; exit 2; }; }
rule() { echo "${RULES[$1]//%A/$2}"; }   # index action -> command line
count_present() {   # how many of the rules are in place (needs root)
    local i n=0
    for i in "${!RULES[@]}"; do
        # shellcheck disable=SC2046
        if $(rule "$i" -C) 2>/dev/null; then n=$((n + 1)); fi
    done
    echo "$n"
}

write_hook() {
    {
        echo '#!/bin/sh'
        echo "$MARK"
        echo '# Installed by testbed/nested/host-guard.sh; remove with: host-guard.sh remove'
        echo '[ "$IFACE" = cnest ] || exit 0'
        echo 'PATH=/usr/sbin:/sbin:/usr/bin:/bin'
        local i
        # A non-zero exit would make ifupdown2 log an error, so a failed insert is logged and swallowed.
        for i in "${!RULES[@]}"; do
            echo "$(rule "$i" -C) 2>/dev/null || $(rule "$i" -I) || logger -t concord-nest-guard \"insert failed: $(rule "$i" -I)\""
        done
        echo 'exit 0'
    } >"$1"
}

cmd=${1:-}
case $cmd in
    install)
        need_root install
        if [[ -e $HOOK ]] && ! grep -qF "$MARK" "$HOOK"; then
            echo "refusing: $HOOK exists and is not ours" >&2; exit 1
        fi
        tmp=$(mktemp)
        trap 'rm -f "$tmp"' EXIT
        write_hook "$tmp"
        install -m 0755 -o root -g root "$tmp" "$HOOK"
        echo "installed $HOOK"
        if ip link show cnest >/dev/null 2>&1; then
            IFACE=cnest "$HOOK"
            present=$(count_present)
            if ((present != ${#RULES[@]})); then
                echo "FAILED: only $present of ${#RULES[@]} guard rules are present after running the hook" >&2
                exit 1
            fi
            echo "cnest is up: ${#RULES[@]} of ${#RULES[@]} rules applied now"
        else
            echo "cnest is not up yet: the rules will be applied when it comes up"
        fi
        ;;
    remove)
        need_root remove
        rc=0
        for i in "${!RULES[@]}"; do
            # shellcheck disable=SC2046
            while $(rule "$i" -C) 2>/dev/null; do
                # shellcheck disable=SC2046
                $(rule "$i" -D) || { echo "could not delete: $(rule "$i" -D)" >&2; rc=1; break; }
            done
        done
        if [[ -e $HOOK ]]; then
            if grep -qF "$MARK" "$HOOK"; then rm -f "$HOOK"; echo "removed $HOOK"; else echo "left $HOOK: not ours" >&2; fi
        else
            echo "no hook to remove"
        fi
        if ((rc)); then echo "some guard rules could NOT be removed (see above)" >&2; exit 1; fi
        echo "guard rules removed"
        ;;
    status)
        if [[ -x $HOOK ]] && grep -qF "$MARK" "$HOOK"; then echo "hook: installed ($HOOK)"; else echo "hook: absent"; fi
        if ip link show cnest >/dev/null 2>&1; then echo "cnest: up"; else echo "cnest: absent"; fi
        if [[ $EUID -eq 0 ]]; then
            present=$(count_present)
            echo "rules: $present of ${#RULES[@]} present"
        else
            echo "rules: not checked (needs root)"
        fi
        ;;
    *)
        echo "usage: host-guard.sh install|remove|status" >&2
        exit 2
        ;;
esac
