#!/usr/bin/env bash
# Turn a Debian 13 (trixie) cloud image into a Proxmox VE 9 node. Runs INSIDE a nested
# node, as root, and is safe to re-run: build.sh copies it over and calls it until it exits 0.
#
#   install-pve.sh --hostname nest1 --ip 10.99.0.11 [--gateway 10.99.0.1] [--dns "1.1.1.1 9.9.9.9"]
#                  --lan-probe HOST_LAN_IP --root-password-file FILE
#
# Exit codes: 0 finished; 10 "a reboot was scheduled, run me again when the node is back"; other = failure.
#
# Follows the Proxmox wiki, "Install Proxmox VE on Debian 13 Trixie":
#   https://pve.proxmox.com/wiki/Install_Proxmox_VE_on_Debian_13_Trixie
# The repository stanza, key URL and key checksum below are copied
# from that page, not from memory. Steps in order, as on the page:
#   1. hostname resolves through /etc/hosts      2. add repo + key, apt full-upgrade
#   3. install the PVE kernel, reboot            4. install proxmox-ve postfix open-iscsi chrony
#   5. remove the Debian kernel                  6. remove os-prober
# Additions that are NOT on the page, each with its reason, are marked "ADDED".
set -euo pipefail

HOST="" IP="" GATEWAY=10.99.0.1 DNS="1.1.1.1 9.9.9.9" ROOT_PW_FILE="" LAN_PROBE=""
while (($#)); do
    case $1 in
        --hostname) HOST=$2; shift 2 ;;
        --ip) IP=$2; shift 2 ;;
        --gateway) GATEWAY=$2; shift 2 ;;
        --dns) DNS=$2; shift 2 ;;
        --lan-probe) LAN_PROBE=$2; shift 2 ;;
        --root-password-file) ROOT_PW_FILE=$2; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ -n $HOST && -n $IP ]] || { echo "need --hostname and --ip" >&2; exit 2; }
[[ $LAN_PROBE =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "need --lan-probe (the host's LAN IPv4 address, for the isolation check)" >&2; exit 2; }
[[ -n $ROOT_PW_FILE ]] || { echo "need --root-password-file (there is no default password)" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 2; }

DOMAIN=concord.test
STATE=/var/lib/concord-nest
KEYRING=/usr/share/keyrings/proxmox-archive-keyring.gpg
# From the wiki page's "verify" step.
KEYRING_SHA256=136673be77aba35dcce385b28737689ad64fd785a797e57897589aed08db6e45
# The uplink's pinned name from Stage B on (see the network step).
PIN_NAME=nic0
export DEBIAN_FRONTEND=noninteractive
APT=(apt-get -y -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef)
mkdir -p "$STATE"
say() { echo "[install-pve $HOST] $*"; }
reboot_and_ask_again() {
    say "scheduling reboot in 5 s; build.sh will re-run this script afterwards"
    systemd-run --quiet --on-active=5 --unit=concord-nest-reboot systemctl reboot
    exit 10
}
running_pve_kernel() { uname -r | grep -q -- '-pve$'; }

# ADDED. Isolation of the nested estate from the LAN. The VM's NIC is on an SDN vnet that is
# not bridged to vmbr0, but the host routes and SNATs it, so a node CAN reach the LAN through
# the host unless it is told not to. This is inside the node, so it is a guard against mistakes,
# not a security boundary against root in the node.
# Two tables. "inet concord_nest" covers traffic of the node itself (output) and routed traffic
# (forward). Guests INSIDE the node are bridged on its vmbr0, and PVE keeps
# net.bridge.bridge-nf-call-iptables=0, so the inet forward chain never sees them; "bridge
# concord_nest" covers those. IPv6 is dropped except neighbour discovery and loopback: the vnet
# has no IPv6 service, but the host's cnest bridge has a link-local address with sshd and
# pveproxy listening on it. Needs apt lists, so the caller runs apt-get update first.
install_isolation() {
    say "installing nftables isolation (tables inet and bridge concord_nest)"
    "${APT[@]}" install nftables >/dev/null
    cat >/etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
# Written by testbed/nested/install-pve.sh. Keeps this node off the LAN and off the
# host's own services. Own table only, so it never touches anything PVE adds.
table inet concord_nest
delete table inet concord_nest
table inet concord_nest {
    set private_nets {
        type ipv4_addr; flags interval
        elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 }
    }
    chain output {
        type filter hook output priority 0; policy accept;
        meta nfproto ipv6 oifname "lo" accept
        meta nfproto ipv6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept
        meta nfproto ipv6 drop
        ct state established,related accept
        oifname "lo" accept
        ip daddr $GATEWAY icmp type echo-request accept
        # sshd's side of a session from the host. The session that loads this file started
        # before any ct rule existed, and the kernel registers conntrack in a netns only once a rule
        # needs it, so that flow is picked up mid-stream and its next packet out is "new", not
        # established. Without this rule it is rejected and the session hangs. No SYN, so a socket
        # bound to port 22 still cannot open a connection to the host this way.
        ip daddr $GATEWAY tcp sport 22 tcp flags & syn == 0 accept
        ip daddr $GATEWAY reject with icmp type admin-prohibited
        ip daddr 10.99.0.0/16 accept
        ip daddr @private_nets reject with icmp type admin-prohibited
    }
    chain input {
        type filter hook input priority 0; policy accept;
        meta nfproto ipv6 iifname "lo" accept
        meta nfproto ipv6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept
        meta nfproto ipv6 drop
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
        meta nfproto ipv6 drop
        ct state established,related accept
        ip daddr $GATEWAY reject with icmp type admin-prohibited
        ip daddr 10.99.0.0/16 accept
        ip daddr @private_nets reject with icmp type admin-prohibited
    }
}

table bridge concord_nest
delete table bridge concord_nest
table bridge concord_nest {
    set private_nets {
        type ipv4_addr; flags interval
        elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 }
    }
    # Frames bridged between nested guests and the node's uplink. Priority -150 is after bridge
    # conntrack (-200) and before the node's own bridge rules.
    chain forward {
        type filter hook forward priority -150; policy accept;
        ether type ip6 drop
        # Stateless on purpose: the only thing a nested guest may send to the host's address is ICMP.
        ip daddr $GATEWAY ip protocol != icmp drop
        ip daddr 10.99.0.0/16 accept
        ip daddr @private_nets drop
    }
}
EOF
    nft -c -f /etc/nftables.conf
    nft -f /etc/nftables.conf
    systemctl enable nftables >/dev/null 2>&1
}

# ADDED. The Debian genericcloud image boots BIOS (SeaBIOS) from a GPT disk and ships
# grub-cloud-amd64, which installs GRUB itself (i386-pc into the disk, x86_64-efi into the ESP)
# from dpkg triggers whenever the GRUB modules change; grub-pc is NOT installed and
# grub-pc/install_devices is empty. proxmox-kernel-*-pve-signed has
# "Recommends: grub-pc | grub-efi-amd64 | ...", and the Proxmox repo carries a newer GRUB than
# Debian's, so the wiki's bare "apt install proxmox-default-kernel" installs grub-pc as a
# recommendation. Its postinst then has no install device, cannot ask (noninteractive) and aborts:
# "You must correct your GRUB install devices before proceeding", dpkg exit 100.
# The kernel is installed without recommends, so grub-pc never lands. Two safety nets:
#  - a half-configured grub-pc left by an earlier failed run is purged (re-entrancy), and
#    dpkg is finished. The purge deletes /etc/default/grub (grub-pc's postrm does it
#    unconditionally), which belongs to grub-cloud-amd64 and holds console=ttyS0 and the serial
#    terminal; the node's only console is vga: serial0. So a copy is kept and put back;
#  - grub-pc/install_devices is preseeded with the boot disk's stable by-id path, so if a later
#    apt step recommends grub-pc anyway its postinst succeeds (it writes the same i386-pc image
#    grub-cloud-amd64 does, to the same disk).
boot_disk_by_id() {
    local src pk l
    src=$(findmnt -no SOURCE /boot) || true
    [[ -n $src ]] || src=$(findmnt -no SOURCE /)
    pk=$(lsblk -no PKNAME "$src" | head -n1)
    [[ -n $pk ]] || return 1
    for l in /dev/disk/by-id/*; do
        [[ $l == *-part* ]] && continue
        [[ $(readlink -f "$l") == "/dev/$pk" ]] && { echo "$l"; return 0; }
    done
    return 1
}
grub_heal_and_preseed() {
    local gst disk
    gst=$(dpkg-query -W -f='${db:Status-Status}' grub-pc 2>/dev/null || true)
    # Taken on every pass and only while no copy exists, so the first pass on any node saves the
    # image's pristine file, and a run killed between the purge and the restore still heals.
    [[ -e $STATE/default-grub.saved || ! -e /etc/default/grub ]] || cp -a /etc/default/grub "$STATE/default-grub.saved"
    case $gst in
        half-configured|half-installed|unpacked)
            say "grub-pc is $gst (left by a failed run): purging it; the image's grub-cloud-amd64 manages GRUB"
            "${APT[@]}" purge grub-pc ;;
    esac
    if [[ ! -e /etc/default/grub ]]; then
        # dpkg treats a missing conffile as removed by the admin and never brings it back, and
        # update-grub without it would drop the serial console for good.
        [[ -e $STATE/default-grub.saved ]] || { say "FAIL: /etc/default/grub is missing and there is no saved copy; refusing to run update-grub without it"; exit 1; }
        say "restoring /etc/default/grub (grub-cloud-amd64's conffile) removed by the grub-pc purge"
        cp -a "$STATE/default-grub.saved" /etc/default/grub
    fi
    if disk=$(boot_disk_by_id); then
        say "preseeding grub-pc/install_devices=$disk (safety net)"
        echo "grub-pc grub-pc/install_devices multiselect $disk" | debconf-set-selections
    else
        say "WARNING: boot disk has no /dev/disk/by-id name; not preseeding grub-pc"
    fi
    # Finish anything else a failed run left unconfigured. Harmless when nothing is pending.
    dpkg --configure -a
}

# ADDED. pve-manager ships /etc/apt/sources.list.d/pve-enterprise.sources as a conffile (checked with
# dpkg -S and dpkg-query Conffiles, pve-manager 9.2.28), pointing at enterprise.proxmox.com, which
# answers 401 without a subscription, so every later "apt-get update" ends in E: lines. Each
# deb822 stanza whose URIs name enterprise.proxmox.com gets
# "Enabled: no", the field sources.list(5) (apt 3.0.4) documents for disabling an entry; any
# Enabled: line already in such a stanza is replaced. Edited rather than deleted, so the file stays
# where pve-manager put it; APT's --force-confold keeps the local edit when an upgrade ships a new
# version of the conffile. Any *.sources file is covered, so a ceph.sources that pveceph writes
# with the enterprise URI is too. $1 is the sources directory, so the
# same code can be tried on a copy.
disable_enterprise_repos() {
    local dir=${1:-/etc/apt/sources.list.d} f tmp
    for f in "$dir"/*.sources; do
        [[ -f $f ]] && grep -q 'enterprise\.proxmox\.com' "$f" || continue
        tmp=$(mktemp "$f.concord.XXXXXX")
        awk '
            function flush(   i) {
                for (i = 1; i <= n; i++) if (!(ent && tolower(buf[i]) ~ /^enabled[[:space:]]*:/)) print buf[i]
                if (ent) print "Enabled: no"
                n = 0; ent = 0
            }
            /^[[:space:]]*$/ { flush(); print; next }
            { buf[++n] = $0; if ($0 !~ /^#/ && index($0, "enterprise.proxmox.com")) ent = 1 }
            END { flush() }
        ' "$f" >"$tmp"
        if cmp -s "$f" "$tmp"; then rm -f "$tmp"; continue; fi
        chmod --reference="$f" "$tmp"
        mv "$tmp" "$f"
        say "apt: disabled the enterprise repository in $f (Enabled: no)"
    done
}

# ADDED. root gets a password so each node's own GUI (:8006) can be logged into as root@pam; the
# nodes are the test ground for every Concord feature. It comes from the operator's file
# (NODE_ROOT_PASSWORD_FILE in site.env), which build.sh copies in and passes as
# --root-password-file. There is no default. It reaches chpasswd on stdin, never on a command line (printf is a builtin, so no argv
# carries it). Set on every round, so a node installed earlier gets it from its final round. sshd
# stays as the image has it (no password or keyboard-interactive login, root by key only); the
# final round checks that.
set_root_password() {
    local pw
    [[ -r $ROOT_PW_FILE ]] || { say "FAIL: cannot read --root-password-file $ROOT_PW_FILE"; exit 1; }
    pw=$(<"$ROOT_PW_FILE")
    [[ -n $pw && $pw != *$'\n'* ]] || { say "FAIL: the root password file must hold one non-empty line"; exit 1; }
    printf 'root:%s\n' "$pw" | chpasswd
    say "root password set (from $ROOT_PW_FILE)"
}
set_root_password

# ---------------------------------------------------------------------------
if [[ -f $STATE/installed ]]; then
    say "already installed; verifying"
else
    # Step 1 of the wiki: the hostname must resolve to this node's non-loopback address.
    say "hostname and /etc/hosts"
    hostnamectl set-hostname "$HOST"
    # ADDED. cloud-init would rewrite /etc/hosts, network config and hostname on every boot.
    # manage_etc_hosts: false here does NOT hold: PVE's generated user-data sets
    # "manage_etc_hosts: true", and user-data outranks cloud.cfg.d, so Stage B disables cloud-init.
    mkdir -p /etc/cloud/cloud.cfg.d
    cat >/etc/cloud/cloud.cfg.d/99-concord-nest.cfg <<EOF
manage_etc_hosts: false
preserve_hostname: true
network: {config: disabled}
EOF
    cat >/etc/hosts <<EOF
127.0.0.1       localhost
$IP   $HOST.$DOMAIN $HOST

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF
    [[ $(hostname --ip-address | tr ' ' '\n' | grep -c "^$IP\$") -ge 1 ]] || { say "hostname --ip-address does not return $IP"; exit 1; }

    grub_heal_and_preseed

    if ! running_pve_kernel; then
        # ---- Stage A: everything up to and including the PVE kernel + reboot ----
        say "apt prerequisites"
        "${APT[@]}" update >/dev/null
        install_isolation
        "${APT[@]}" install ca-certificates curl gnupg >/dev/null

        # Step 2: repository (deb822) and key, verbatim from the wiki page.
        say "adding the Proxmox VE repository"
        cat >/etc/apt/sources.list.d/pve-install-repo.sources <<EOL
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: trixie
Components: pve-no-subscription
Signed-By: $KEYRING
EOL
        curl -fsSL https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg -o "$KEYRING"
        got=$(sha256sum "$KEYRING" | cut -d' ' -f1)
        [[ $got == "$KEYRING_SHA256" ]] || { say "keyring checksum mismatch: $got (wiki says $KEYRING_SHA256); aborting"; exit 1; }
        "${APT[@]}" update
        "${APT[@]}" full-upgrade

        # Step 3: kernel first, then reboot into it.
        # ADDED: --no-install-recommends, see grub_heal_and_preseed. On the wiki this is a bare
        # "apt install proxmox-default-kernel", which on the Debian cloud image drags in grub-pc.
        say "installing the PVE kernel"
        "${APT[@]}" install --no-install-recommends proxmox-default-kernel
        # ADDED. Lets Proxmox show this VM's address and shut it down cleanly.
        "${APT[@]}" install qemu-guest-agent >/dev/null || true
        reboot_and_ask_again
    fi

    # ---- Stage B: running the PVE kernel ----
    say "running kernel $(uname -r); installing proxmox-ve"
    echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections
    echo "postfix postfix/mailname string $HOST.$DOMAIN" | debconf-set-selections
    # Step 4.
    "${APT[@]}" install proxmox-ve postfix open-iscsi chrony
    disable_enterprise_repos

    # Step 5. The wiki command is: apt remove linux-image-amd64 'linux-image-6.12*'
    # The cloud image ships the cloud kernel flavour instead, so remove whatever Debian
    # linux-image packages are installed (the PVE kernels are named proxmox-kernel-*).
    say "removing the Debian kernel"
    # Only installed (ii), non-PVE packages: the glob also matches not-installed (un) rows and a
    # virtual name that the PVE signed kernel Provides, which apt would otherwise be handed.
    mapfile -t debian_kernels < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'linux-image-*' 2>/dev/null | awk '$1 == "ii" && $2 !~ /-pve/ {print $2}' | sort -u)
    if ((${#debian_kernels[@]})); then "${APT[@]}" remove "${debian_kernels[@]}"; fi
    update-grub

    # Step 6.
    say "removing os-prober"
    if dpkg -s os-prober >/dev/null 2>&1; then "${APT[@]}" remove os-prober; fi

    # ADDED. PVE needs ifupdown2 and a bridge (vmbr0) for its own guests. The wiki points to
    # the PVE network docs for this. The node's address moves onto vmbr0, as on a normal PVE install.
    say "network: ifupdown2 + vmbr0"
    nic=$(ip -o -4 route get "$GATEWAY" | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)
    [[ -n $nic ]] || { say "cannot determine the NIC"; exit 1; }
    [[ -e /sys/class/net/$nic/device ]] || { say "FAIL: the route to $GATEWAY leaves via '$nic', which is not a physical NIC"; exit 1; }
    mac=$(<"/sys/class/net/$nic/address")
    # ADDED. Pin the uplink's name, because the name it has now does not survive the reboot below.
    # On the cloud image the NIC is "eth0" only because cloud-init's netplan yaml says
    # "set-name: eth0" and netplan's generator turns that into /run/systemd/network/10-netplan-eth0.link
    # at every boot. That yaml is moved aside below, so without a pin the next boot names it by
    # 99-default.link's policy (ens18 on these VMs) and vmbr0 would come up with no port.
    # The pin is the file PVE 9's own pve-network-interface-pinning writes: same directory, the
    # "50-pmx-<name>.link" file name and the same [Match] MACAddress= / Type=ether, [Link] Name=
    # contents (PVE/CLI/pve_network_interface_pinning.pm, pve-manager 9.2.28), and "nic0" is that
    # tool's default prefix. So PVE treats it as an existing pin. The tool itself is not run: it
    # writes interfaces.new for pvenetcommit to swap in at boot and rewrites firewall and SDN
    # config; here the script writes /etc/network/interfaces itself, with the pinned name.
    # "nic0" is outside the kernel's eth* namespace, so it cannot race with kernel naming.
    # The initramfs does not carry /usr/local/lib/systemd/network (initramfs-tools' udev hook copies
    # only /usr/lib and /etc), so the NIC may get another name in the initramfs. The real root's
    # udev then renames it on coldplug: nothing has brought it up yet, and networking.service waits
    # for "udevadm settle" (ifupdown2-pre.service) before it runs ifup. PVE relies on the same.
    PIN_DIR=/usr/local/lib/systemd/network
    mkdir -p "$PIN_DIR"
    cat >"$PIN_DIR/50-pmx-$PIN_NAME.link" <<EOF
[Match]
MACAddress=$mac
Type=ether

[Link]
Name=$PIN_NAME
EOF
    # A staged PVE edit in interfaces.new is moved over interfaces at the next boot by
    # pvenetcommit.service (pve-manager, Before=sysinit.target), which would replace everything
    # written below. One is always there on a node that went through step 4: ifupdown2's postinst
    # (3.3.0-1+pmx14, first configure, no /proxmox_install_mode) runs proxmox_compatibility(),
    # which reads interfaces through PVE::INotify and writes it back, and INotify's write path for
    # /etc/network/interfaces is the shadow file interfaces.new (libpve-common-perl, INotify.pm
    # $shadowfiles). The image has no interfaces file, so that one holds only lo and
    # "iface eth0 inet manual". The script owns the node's network config here, so any staged
    # edit is stale.
    rm -f /etc/network/interfaces.new
    ifaces_want=$(cat <<EOF
auto lo
iface lo inet loopback

iface $PIN_NAME inet manual

auto vmbr0
iface vmbr0 inet static
    address $IP/24
    gateway $GATEWAY
    bridge-ports $PIN_NAME
    bridge-stp off
    bridge-fd 0

source /etc/network/interfaces.d/*
EOF
)
    printf '%s\n' "$ifaces_want" >/etc/network/interfaces
    rm -f /etc/network/interfaces.d/50-cloud-init /etc/network/interfaces.d/eth0
    if [[ -d /etc/netplan ]]; then mkdir -p /root/netplan-disabled && mv /etc/netplan/*.yaml /root/netplan-disabled/ 2>/dev/null || true; fi
    # The .link files netplan generated in this boot. With the yaml gone nothing regenerates them,
    # but until the reboot they still win over the pin (10- sorts before 50-) and would make the
    # check below predict the old name.
    rm -f /run/systemd/network/10-netplan-*.link
    # ADDED. cloud-init's update_etc_hosts runs on every boot and, because PVE's user-data
    # says "manage_etc_hosts: true", replaces /etc/hosts with "127.0.1.1 <host>". pmxcfs then
    # cannot resolve the node name to a non-loopback address and pve-cluster fails. The node needs nothing more from cloud-init: the SSH key and host
    # keys are in place and the network is ifupdown2's. The marker file is the switch every
    # cloud-init unit checks (ConditionPathExists=!/etc/cloud/cloud-init.disabled, cloud-init 25.1).
    touch /etc/cloud/cloud-init.disabled
    # Masked, not just disabled: systemd-networkd.socket would otherwise start it again. No --now.
    # Masking reloads systemd, which then refuses networkd's watchdog pings and kills it about
    # three minutes later. The address and default route stay on the NIC
    # only because nothing removes them; nothing manages the link until the reboot that follows.
    systemctl mask systemd-networkd.service systemd-networkd.socket systemd-networkd-wait-online.service systemd-resolved.service >/dev/null 2>&1 || true
    if compgen -G '/etc/systemd/network/*.network' >/dev/null; then
        mkdir -p /root/systemd-network-disabled && mv /etc/systemd/network/*.network /root/systemd-network-disabled/
    fi
    # The PVE GUI owns DNS; a symlinked stub resolv.conf would be overwritten (wiki: Troubleshooting).
    rm -f /etc/resolv.conf
    for ns in $DNS; do echo "nameserver $ns"; done >/etc/resolv.conf
    # ifupdown2 takes its lock in /run/network/.lock and reports any failure to open it as
    # "Another instance of this program is already running"; only networking.service creates the
    # directory, and it has not run in this boot because the cloud image came up on networkd.
    mkdir -p /run/network
    # ifupdown2's syntax check tests every attribute against its addon's declared range, and
    # addons/bridge.py declares bridge-fd as 2-255 (ifupdown2 3.3.0-1+pmx14), so PVE's own
    # "bridge-fd 0" always fails it. A real ifup/ifreload never applies that range, and with
    # STP off the forward delay does not hold up forwarding. The stanza keeps the line anyway: PVE's
    # writer (PVE/Network/Interfaces.pm) emits "bridge-fd 0" for every STP-off bridge and would add
    # it back on the first GUI network edit. So the gate checks a copy without exactly that line;
    # any other bridge-fd value stays in the copy and is checked. ifreload has no -i, ifup does.
    ifcheck=$(mktemp /tmp/concord-nest-interfaces.XXXXXX)
    sed '/^[[:space:]]*bridge-fd[[:space:]]\+0[[:space:]]*$/d' /etc/network/interfaces >"$ifcheck"
    if ! ifup --syntax-check --all --interfaces "$ifcheck"; then
        rm -f "$ifcheck"
        say "ifupdown2 rejected the generated /etc/network/interfaces"; exit 1
    fi
    rm -f "$ifcheck"
    # Pre-reboot gate. Ask udev what the next boot's coldplug ("add") will call this NIC, from the
    # .link files on disk now, and refuse to reboot unless it is the pin and the bridge uses it.
    # A wrong answer here strands the node off the network; the way back in is the guest agent
    # (docs/TESTBED.md, "Verify the estate").
    link_out=$(udevadm test-builtin -a add net_setup_link "/sys/class/net/$nic" 2>/dev/null) || true
    link_file=$(sed -n 's/^ID_NET_LINK_FILE=//p' <<<"$link_out")
    link_name=$(sed -n 's/^ID_NET_NAME=//p' <<<"$link_out")
    if [[ $link_file != "$PIN_DIR/50-pmx-$PIN_NAME.link" || $link_name != "$PIN_NAME" ]]; then
        say "FAIL: after the reboot udev would apply '${link_file:-none}' and name the NIC '${link_name:-unknown}', not $PIN_NAME; not rebooting"
        exit 1
    fi
    grep -Eq "^[[:space:]]*bridge-ports[[:space:]]+$PIN_NAME[[:space:]]*$" /etc/network/interfaces || { say "FAIL: /etc/network/interfaces does not bridge $PIN_NAME; not rebooting"; exit 1; }
    say "network: NIC $nic ($mac) is pinned as $PIN_NAME from the next boot; vmbr0 bridges $PIN_NAME"

    # ADDED. The emulated i6300esb watchdog is the whole reason these nodes exist (self-fencing).
    # proxmox-kernel blacklists every hardware watchdog driver, i6300esb included
    # (/lib/modprobe.d/blacklist_proxmox-kernel-*.conf), so neither udev nor modules-load.d loads
    # it. watchdog-mux opens /dev/watchdog at boot, and if there is none it modprobes
    # $WATCHDOG_MODULE, falling back to softdog. That variable comes from
    # /etc/default/pve-ha-manager (watchdog-mux.service: EnvironmentFile=-/etc/default/pve-ha-manager;
    # the shipped file: "# select watchdog module (default is softdog)"). An explicit modprobe
    # ignores the blacklist. watchdog-mux then ARMS the device and keeps it fed until something
    # else takes over; with action=reset, a dead watchdog-mux resets this VM.
    /usr/sbin/modinfo i6300esb >/dev/null || { say "FAIL: no i6300esb module in kernel $(uname -r)"; exit 1; }
    hacfg=/etc/default/pve-ha-manager
    if grep -q '^WATCHDOG_MODULE=' "$hacfg" 2>/dev/null; then
        sed -i 's/^WATCHDOG_MODULE=.*/WATCHDOG_MODULE=i6300esb/' "$hacfg"
    else
        # The shipped file (pve-ha-manager 5.2.5) has no trailing newline, so a bare append would
        # land on the "#WATCHDOG_MODULE=ipmi_watchdog" comment and systemd would ignore it.
        # '$a\' adds a newline only when the last line lacks one.
        if [[ -s $hacfg ]]; then sed -i '$a\' "$hacfg"; fi
        echo WATCHDOG_MODULE=i6300esb >>"$hacfg"
    fi
    # Left by earlier versions of this script; the blacklist made it a no-op.
    rm -f /etc/modules-load.d/concord-nest-watchdog.conf
    # Pre-reboot gate, as for the NIC: once $STATE/installed exists this stage never runs again,
    # so a setting that systemd's EnvironmentFile= would not see must fail here, not in the final round.
    grep -qx 'WATCHDOG_MODULE=i6300esb' "$hacfg" || { say "FAIL: $hacfg has no active 'WATCHDOG_MODULE=i6300esb' line; not rebooting"; exit 1; }
    say "watchdog: $hacfg sets WATCHDOG_MODULE=i6300esb from the next boot"

    # Last pre-reboot gate, after every step that could have touched the network config.
    # The one unit in the boot path that rewrites interfaces is pvenetcommit.service, and it acts
    # only on interfaces.new (checked on a built node: no other unit, udev rule or if-*.d hook writes
    # the file; pve-sdn-commit writes interfaces.d/sdn only). cloud-init, which would rewrite
    # /etc/hosts, is disabled. So: nothing staged, the file is still the one written above, and
    # the node name still resolves to this node's address.
    [[ ! -e /etc/network/interfaces.new ]] || { say "FAIL: /etc/network/interfaces.new exists; pvenetcommit would move it over interfaces at boot; not rebooting"; exit 1; }
    [[ $(</etc/network/interfaces) == "$ifaces_want" ]] || { say "FAIL: /etc/network/interfaces changed after the network step; not rebooting"; exit 1; }
    [[ -e /etc/cloud/cloud-init.disabled ]] || { say "FAIL: cloud-init is not disabled and would rewrite /etc/hosts at boot; not rebooting"; exit 1; }
    [[ $(hostname --ip-address | tr ' ' '\n' | grep -c "^$IP\$") -ge 1 ]] || { say "FAIL: hostname --ip-address does not return $IP; not rebooting"; exit 1; }
    say "network: nothing staged in interfaces.new; interfaces is unchanged; cloud-init is disabled"

    touch "$STATE/installed"
    reboot_and_ask_again
fi

# ---- Verification (final round): print facts, fail loudly on the ones that matter ----
say "verification"
# Also heals nodes installed before this step existed: the final round always runs this branch.
disable_enterprise_repos
running_pve_kernel || { say "FAIL: not running a PVE kernel: $(uname -r)"; exit 1; }
pveversion
# pmxcfs (pve-cluster) refuses to start unless the node name resolves to a non-loopback address.
[[ $(hostname --ip-address | tr ' ' '\n' | grep -c "^$IP\$") -ge 1 ]] || { say "FAIL: hostname --ip-address does not return $IP; /etc/hosts was rewritten (cloud-init?)"; exit 1; }
# build.sh starts this round as soon as sshd answers, and sshd comes up before the PVE services
# finish starting (pveproxy takes about 2 s), so give them time before calling one dead.
# watchdog-mux is static, started through pve-ha-lrm/crm; /dev/watchdog appears only once it runs.
for svc in pve-cluster pvedaemon pveproxy watchdog-mux; do
    for _ in $(seq 1 60); do systemctl is-active --quiet "$svc" && break; sleep 2; done
    systemctl is-active --quiet "$svc" || { say "FAIL: $svc is not active after 2 minutes"; exit 1; }
done
say "bridge: $(ip -o -4 addr show vmbr0 | awk '{print $4}')"
[[ -e /sys/class/net/vmbr0/brif/$PIN_NAME ]] || { say "FAIL: $PIN_NAME is not a port of vmbr0"; exit 1; }
# /dev/watchdog is the legacy device of watchdog0. softdog would also pass an "exists" check, so
# require the i6300esb driver's identity string, the i6300esb module in use, and no softdog.
# i6300esb registers watchdog0 without a parent (/sys/devices/virtual/watchdog/watchdog0,
# no "device" link), so the module cannot be read through watchdog0. It is in use when
# watchdog-mux holds /dev/watchdog open (refcnt >= 1) or when the PCI device is bound to the
# driver, whose name is "i6300ESB timer" (PCI 0000:00:04.0 on these VMs).
[[ -e /dev/watchdog ]] || { say "FAIL: no /dev/watchdog"; exit 1; }
wd_id=$(cat /sys/class/watchdog/watchdog0/identity 2>/dev/null || echo unknown)
wd_ref=$(cat /sys/module/i6300esb/refcnt 2>/dev/null || echo 0)
wd_bound=no
if compgen -G '/sys/bus/pci/drivers/i6300ESB timer/0000:*' >/dev/null; then wd_bound=yes; fi
wd_soft=no
if [[ -e /sys/module/softdog ]]; then wd_soft=yes; fi
if [[ $wd_id != "i6300ESB timer" || $wd_soft == yes ]] || ! [[ $wd_ref =~ ^[0-9]+$ && $wd_ref -ge 1 || $wd_bound == yes ]]; then
    say "FAIL: /dev/watchdog is '$wd_id' (i6300esb refcnt $wd_ref, PCI bound $wd_bound, softdog loaded $wd_soft), not the i6300esb alone; check WATCHDOG_MODULE in /etc/default/pve-ha-manager"
    exit 1
fi
say "watchdog: /dev/watchdog present, identity: $wd_id"
probe() { timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }
# A refused connect proves nothing when nothing listens there, so probe ports that DO listen:
# sshd on the host's LAN address and on the vnet gateway, and pveproxy on the gateway.
nft list table inet concord_nest >/dev/null 2>&1 || { say "FAIL: nft table inet concord_nest is not loaded"; exit 1; }
nft list table bridge concord_nest >/dev/null 2>&1 || { say "FAIL: nft table bridge concord_nest is not loaded"; exit 1; }
# Positive control: if this fails, a failing probe below could just mean no network.
probe download.proxmox.com 443 || { say "FAIL: positive control (download.proxmox.com:443) not reachable, so the isolation probes prove nothing"; exit 1; }
for target in "$LAN_PROBE:22" "$GATEWAY:22" "$GATEWAY:8006"; do
    if probe "${target%:*}" "${target#*:}"; then
        say "FAIL: isolation is not working ($target is reachable)"; exit 1
    fi
done
say "isolation: LAN and host services unreachable (ok)"
# The root password is for the GUI only; SSH must stay key-only.
sshd_cfg=$(sshd -T 2>/dev/null) || { say "FAIL: sshd -T failed"; exit 1; }
grep -qx 'passwordauthentication no' <<<"$sshd_cfg" || { say "FAIL: sshd accepts password authentication"; exit 1; }
grep -qx 'kbdinteractiveauthentication no' <<<"$sshd_cfg" || { say "FAIL: sshd accepts keyboard-interactive authentication"; exit 1; }
grep -Eqx 'permitrootlogin (without-password|prohibit-password|no)' <<<"$sshd_cfg" || { say "FAIL: sshd lets root log in with a password"; exit 1; }
say "ssh: key-only; the root password is not accepted over SSH (ok)"
# download.proxmox.com serves no certificate for its own name over HTTPS (curl exit 60),
# so the HTTPS form always warned. This is the URL apt uses.
curl -fsSI --max-time 15 http://download.proxmox.com/debian/ >/dev/null && say "internet: reachable (ok)" || say "WARNING: internet not reachable"
# Every configured repository must answer. An enterprise repo left enabled shows up here as
# "E: Failed to fetch ... 401 Unauthorized"; so would any other broken source.
# apt-get update does not wait for /var/lib/apt/lists/lock, and the apt-daily timers (Persistent=true)
# can fire right after the reboot before this round, so a healthy node would fail on a held lock.
# Retry only on a lock error; the check below then judges the last output, so a lock that never
# frees still fails with its own message.
apt_out=""
for attempt in $(seq 1 30); do
    apt_out=$(apt-get update 2>&1) || true
    grep -Eq '^E: (Could not get lock|Unable to lock)' <<<"$apt_out" || break
    [ "$attempt" -lt 30 ] || break
    say "apt: lists lock is held (attempt $attempt/30), waiting 10 s"
    sleep 10
done
if grep -q '^E:' <<<"$apt_out"; then
    say "FAIL: apt-get update reports errors:"
    grep '^E:' <<<"$apt_out" | sed 's/^/    /'
    exit 1
fi
say "apt: apt-get update has no errors (ok)"
say "ok"
