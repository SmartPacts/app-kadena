#!/bin/sh
# Builds the heap measurement app (never shipped) for one device and puts it where
# the Ragger tests find the app, target/<device>/release/kadena, replacing the
# normal build there. tests/test_heap_probe.py then measures the largest review;
# rebuild normally (cargo ledger build <device>) before running the other tests.
#
# The build is made in a copy of the source whose manifest turns off the SDK's
# default features (its allocator), so that the app's own wrapped allocator is the
# global one. Run it in the dev-tools image, from the repository root.
set -eu
device=$1
root=$(pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tar -cf - --exclude=./target --exclude=./.git . | tar -xf - -C "$tmp"
sed -i 's/^\(ledger_device_sdk = { version = "[^"]*",\) features/\1 default-features = false, features/' "$tmp/Cargo.toml"
grep -q '^ledger_device_sdk = .*default-features = false' "$tmp/Cargo.toml" || {
    echo "heap-probe: could not turn off the SDK's default features in Cargo.toml" >&2
    exit 1
}
(cd "$tmp" && cargo ledger build "$device" -- --features heap-probe)
mkdir -p "$root/target/$device/release"
cp "$tmp/target/$device/release/kadena" "$root/target/$device/release/kadena"
echo "heap-probe: measurement app for $device in target/$device/release/kadena"
