# shellcheck shell=bash
# Loads testbed/site.env for build.sh, teardown.sh, darken.sh and pve.sh. Sourced, never run.
#
# Not part of the root-run set: net-snapshot.sh, net-rollback.sh and host-guard.sh use only lib.sh,
# which holds no site value, so root never reads a file an unprivileged account can edit.
# The file is parsed, not sourced, and only the keys below are accepted: it cannot run code and
# cannot set anything else (the VMID range, names and markers are readonly in lib.sh besides).

SITE_KEYS="NODE PVE_API PVE_FINGERPRINT PVE_TOKEN_FILE HOST_LAN_IP STORAGE_MOUNTPOINT SECRETS_DIR NODE_ROOT_PASSWORD_FILE"
SITE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

site_die() { echo "ABORT: site config: $*" >&2; exit 1; }

# Regular file, owned by the caller, with none of the forbidden mode bits.
site_private_file() {   # what path forbidden-mode(octal digits for find -perm /)
    [[ -f $2 && -r $2 ]] || site_die "$1 is missing or not a readable file: $2"
    [[ $(stat -L -c %u -- "$2") == "$EUID" ]] || site_die "$1 is not owned by you: $2"
    [[ -z $(find -L "$2" -maxdepth 0 -perm "/$3") ]] || site_die "$1 has mode $(stat -L -c %a -- "$2"), which is too open: $2 (chmod 600)"
}

site_load() {
    local file=${CONCORD_SITE_ENV:-$SITE_DIR/../site.env} line key val n=0 octet
    local path_re='^/[A-Za-z0-9._/-]+$' ip_re='^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$'
    [[ -e $file ]] || site_die "$file does not exist. Copy testbed/site.env.example to testbed/site.env and fill it in (or set CONCORD_SITE_ENV)"
    site_private_file "the site config" "$file" 022
    # Start clean: a value inherited from the environment must not stand in for a missing key.
    for key in $SITE_KEYS; do unset "$key"; done
    while IFS= read -r line || [[ -n $line ]]; do
        n=$((n + 1))
        [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
        [[ $line =~ ^([A-Z_]+)=(.*)$ ]] || site_die "$file:$n is not KEY=value"
        key=${BASH_REMATCH[1]} val=${BASH_REMATCH[2]}
        [[ " $SITE_KEYS " == *" $key "* ]] || site_die "$file:$n: unknown key $key"
        [[ -z ${!key+x} ]] || site_die "$file:$n: $key is set twice"
        [[ -n $val ]] || site_die "$key is empty"
        [[ $val != *CHANGE_ME* ]] || site_die "$key is still the example's placeholder"
        case $val in 192.0.2.* | 198.51.100.* | 203.0.113.*) site_die "$key is still a documentation address (RFC 5737)" ;; esac
        printf -v "$key" %s "$val"
    done <"$file"
    for key in $SITE_KEYS; do [[ -n ${!key+x} ]] || site_die "$key is not set in $file"; done

    [[ $NODE =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]] || site_die "NODE is not a node name"
    [[ $PVE_API =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?:[0-9]{1,5}$ ]] || site_die "PVE_API is not host:port"
    [[ $PVE_FINGERPRINT =~ ^([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$ ]] || site_die "PVE_FINGERPRINT is not a SHA-256 fingerprint (32 hex pairs)"
    [[ $HOST_LAN_IP =~ $ip_re ]] || site_die "HOST_LAN_IP is not an IPv4 address"
    for octet in "${BASH_REMATCH[@]:1}"; do ((10#$octet <= 255)) || site_die "HOST_LAN_IP is not an IPv4 address"; done
    for key in PVE_TOKEN_FILE STORAGE_MOUNTPOINT SECRETS_DIR NODE_ROOT_PASSWORD_FILE; do
        # Absolute and plain: these reach command lines, API parameters and ssh.
        [[ ${!key} =~ $path_re && ${!key} != */ && ${!key} != *//* && ${!key}/ != */../* && ${!key}/ != */./* ]] \
            || site_die "$key is not a plain absolute path"
    done
}

# What build.sh, teardown.sh and darken.sh need on top of the API settings.
site_load_estate() {
    site_load
    [[ -d $SECRETS_DIR ]] || site_die "SECRETS_DIR does not exist: $SECRETS_DIR"
    STORAGE_PATH=$STORAGE_MOUNTPOINT/concord-nest
    SEC_DIR=$SECRETS_DIR
    SSH_KEY=$SEC_DIR/concord-nest_ed25519
    TOKEN_FILE=$SEC_DIR/concord-nest-token.txt
    KNOWN_HOSTS=$SEC_DIR/concord-nest_known_hosts
    PVE_SH=${PVE_SH:-$SITE_DIR/pve.sh}
    ROOT_PW_FILE=$NODE_ROOT_PASSWORD_FILE
}
