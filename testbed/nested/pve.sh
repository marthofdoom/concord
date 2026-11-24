#!/usr/bin/env bash
# One PVE API call with the administrator token from testbed/site.env.
#
#   pve.sh [curl args...] /api/path        e.g. pve.sh /version
#                                               pve.sh -X POST --data-urlencode k=v /some/path
#
# The path comes LAST; before it, the request options listed below go to curl unchanged. Like curl
# without -f, it exits 0 on an HTTP error and prints the body.
#
# The token is read from a 0600 file you own and reaches curl as a header read from a pipe: it is
# never on a command line, in the environment, or printed.
#
# TLS: the server's certificate must have the SHA-256 fingerprint in PVE_FINGERPRINT. curl can only
# pin a public key, so the served certificate is checked against the fingerprint first and curl is
# then pinned to that certificate's key. -k only turns off the CA/name check (PVE's certificate is
# usually self-signed); the pin still applies, and a server without that private key cannot
# complete the handshake.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=site.sh
. "$HERE/site.sh"
site_load
[[ $# -ge 1 && ${*: -1} == /* ]] || { echo "usage: pve.sh [curl args...] /api/path" >&2; exit 2; }
site_private_file "the API token file" "$PVE_TOKEN_FILE" 077

# The pin options below only bind the URL at the end. Anything curl would read as another URL
# (a bare word is one), a new request (--next, -:), more options (-K) or verbose output (which prints
# the token header) must not get through, so only these options pass, each in its own argument.
args=("${@:1:$#-1}")
i=0
while ((i < ${#args[@]})); do
    case ${args[i]} in
        -X | --request | -d | --data | --data-urlencode | --data-raw | --data-binary | -F | --form | --form-string | -w | --write-out | -o | --output | -m | --max-time | --connect-timeout)
            ((i + 1 < ${#args[@]})) || { echo "pve.sh: ${args[i]} needs a value" >&2; exit 2; }
            i=$((i + 2)) ;;
        -G | --get | -s | --silent | -S | --show-error | -f | --fail | --fail-with-body | -i | --include) i=$((i + 1)) ;;
        *) echo "pve.sh: curl argument $((i + 1)) is not one this script passes on (no extra URLs, --next, -K/--config, -v or --trace)" >&2; exit 2 ;;
    esac
done
cert=$(timeout 15 openssl s_client -connect "$PVE_API" </dev/null 2>/dev/null | openssl x509 2>/dev/null) \
    || { echo "pve.sh: no certificate from $PVE_API" >&2; exit 1; }
got=$(openssl x509 -noout -fingerprint -sha256 <<<"$cert")
[[ ${got##*=} == "${PVE_FINGERPRINT^^}" ]] \
    || { echo "pve.sh: the certificate at $PVE_API does not match PVE_FINGERPRINT; refusing to send the token" >&2; exit 1; }
pin=$(openssl x509 -noout -pubkey <<<"$cert" | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | openssl base64 -A)
[[ $pin =~ ^[A-Za-z0-9+/]{43}=$ ]] || { echo "pve.sh: cannot derive the key pin" >&2; exit 1; }

# -q first: no ~/.curlrc. The pin, protocol and proxy options come after the caller's arguments so
# they cannot be loosened. -g: no brace or bracket globbing of the path into several URLs.
exec curl -q -sS --max-time 30 \
    -H @<(printf 'Authorization: PVEAPIToken=%s\n' "$(tr -d '\r\n' <"$PVE_TOKEN_FILE")") \
    "${args[@]}" \
    -g -k --pinnedpubkey "sha256//$pin" --proto =https --no-location --noproxy '*' \
    "https://$PVE_API/api2/json${*: -1}"
