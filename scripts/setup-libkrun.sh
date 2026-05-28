#!/usr/bin/env bash
# Build and install libkrun into a local vendor directory.
# Idempotent — skips if the correct version is already installed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIBKRUN_VERSION="$(cat "$REPO_ROOT/LIBKRUN_VERSION")"
LIBKRUNFW_VERSION="$(cat "$REPO_ROOT/LIBKRUNFW_VERSION")"
VENDOR_DIR="${PLAYPENCIL_LIBKRUN_DIR:-$REPO_ROOT/vendor/libkrun}"
STAMP="libkrun=$LIBKRUN_VERSION libkrunfw=$LIBKRUNFW_VERSION"

# Skip if already built at the correct versions.
if [ -f "$VENDOR_DIR/.version" ] && [ "$(cat "$VENDOR_DIR/.version")" = "$STAMP" ]; then
    echo "libkrun $LIBKRUN_VERSION + libkrunfw $LIBKRUNFW_VERSION already installed at $VENDOR_DIR"
    echo "PKG_CONFIG_PATH=$VENDOR_DIR/lib64/pkgconfig"
    exit 0
fi

echo "Building libkrun $LIBKRUN_VERSION into $VENDOR_DIR ..."

TARBALL_URL="https://github.com/containers/libkrun/archive/refs/tags/${LIBKRUN_VERSION}.tar.gz"
SRC_DIR="$REPO_ROOT/vendor/libkrun-src-$$"

mkdir -p "$REPO_ROOT/vendor"
trap 'rm -rf "$SRC_DIR"' EXIT

echo "Downloading $TARBALL_URL ..."
curl -fsSL "$TARBALL_URL" | tar xz -C "$REPO_ROOT/vendor"
# GitHub tarballs extract as libkrun-<tag-without-v>/
mv "$REPO_ROOT/vendor/libkrun-${LIBKRUN_VERSION#v}" "$SRC_DIR"

echo "Building (BLK=1 NET=1) ..."
make -C "$SRC_DIR" BLK=1 NET=1 -j"$(nproc)"

echo "Installing to $VENDOR_DIR ..."
rm -rf "$VENDOR_DIR"
PREFIX="$VENDOR_DIR" make -C "$SRC_DIR" install

# Install pre-built libkrunfw (guest kernel firmware).
LIBKRUNFW_URL="https://github.com/containers/libkrunfw/releases/download/${LIBKRUNFW_VERSION}/libkrunfw-x86_64.tgz"
echo "Downloading libkrunfw $LIBKRUNFW_VERSION ..."
curl -fsSL "$LIBKRUNFW_URL" | tar xz -C "$VENDOR_DIR"

echo "$STAMP" > "$VENDOR_DIR/.version"
echo ""
echo "Done. Use:"
echo "  export PKG_CONFIG_PATH=$VENDOR_DIR/lib64/pkgconfig"
echo "  export LD_LIBRARY_PATH=$VENDOR_DIR/lib64"
