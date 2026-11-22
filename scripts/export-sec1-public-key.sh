#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 public-key.der" >&2
    exit 2
fi

input=$1
[ -r "$input" ] || { echo "cannot read $input" >&2; exit 1; }

# OpenSC exports an EC SubjectPublicKeyInfo DER object. For a P-256 key,
# the uncompressed SEC1 point is exactly the final 65 bytes.
point=$(mktemp)
trap 'rm -f "$point"' EXIT HUP INT TERM
openssl pkey -pubin -inform DER -in "$input" -pubout -outform DER |
    tail -c 65 > "$point"

[ "$(wc -c < "$point" | tr -d ' ')" = "65" ] || {
    echo "expected a 65-byte uncompressed P-256 point" >&2
    exit 1
}
[ "$(od -An -t x1 -N1 "$point" | tr -d ' \n')" = "04" ] || {
    echo "public key is not an uncompressed SEC1 point" >&2
    exit 1
}
base64 -w0 "$point"
echo
