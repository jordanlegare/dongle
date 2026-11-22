#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CONFIG_FILE="${DONGLE_UEFI_CONFIG:-$ROOT_DIR/config/uefi-stage.env}"

if [ ! -r "$CONFIG_FILE" ]; then
  echo "Missing UEFI build config: $CONFIG_FILE" >&2
  echo "Copy config/uefi-stage.example.env to config/uefi-stage.env and edit it." >&2
  exit 2
fi

# shellcheck disable=SC1090
set -a
. "$CONFIG_FILE"
set +a

: "${DONGLE_UEFI_SERVER:?Set DONGLE_UEFI_SERVER}"
: "${DONGLE_UEFI_USER_ID:?Set DONGLE_UEFI_USER_ID}"
: "${DONGLE_UEFI_DONGLE_ID:?Set DONGLE_UEFI_DONGLE_ID}"
: "${DONGLE_UEFI_ASSET_ID:?Set DONGLE_UEFI_ASSET_ID}"
: "${DONGLE_UEFI_NEXT_BOOT_DEVICE_PATH:?Set the full next-stage UEFI device path}"

case "$DONGLE_UEFI_SERVER" in
  https://*) ;;
  *) echo "DONGLE_UEFI_SERVER must use https://" >&2; exit 2 ;;
esac

cd "$ROOT_DIR"
rustup target add x86_64-unknown-uefi
cargo build --manifest-path uefi-stage/Cargo.toml \
  --target x86_64-unknown-uefi --release

echo "UEFI application: $ROOT_DIR/target/x86_64-unknown-uefi/release/dongle_uefi_stage.efi"
echo "Sign it with the Secure Boot signing key trusted by the target firmware."
