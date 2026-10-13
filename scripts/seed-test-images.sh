#!/usr/bin/env bash
# Populate the offline test image-cache seed by pulling the digest-pinned test
# images once, from a registry that is not subject to Docker Hub pull limits.
#
# The seed lets `make test` resolve these images fully offline (see
# tests/conftest.py: seed_image_cache). It only needs to run once per machine;
# the green test run uses whatever is already in the seed directory.
#
# Override the destination with PLAYPENCIL_TEST_IMAGE_CACHE (matches conftest).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO_ROOT/bin/playpencil"
SEED="${PLAYPENCIL_TEST_IMAGE_CACHE:-$HOME/.cache/playpencil/test-images}"

# Digest-pinned test images (each ref pins the platform-manifest digest, which is
# the image-cache key). Alpine is pulled from the public ECR mirror of the
# official image (content-identical to Docker Hub, so the digests match); the
# minimal no-tail image used for image-independence is distroless/static.
IMAGES=(
    "public.ecr.aws/docker/library/alpine@sha256:b58899f069c47216f6002a6850143dc6fae0d35eb8b0df9300bbe6327b9c2171"
    "gcr.io/distroless/static-debian12@sha256:7d14daf425206f9e79b463e57226c1d6500a6b42f4923d5f0a9a413657f5774f"
)

if [ ! -x "$BIN" ]; then
    echo "playpencil binary not found at $BIN — run 'make all' first." >&2
    exit 1
fi

DATA_DIR="$(mktemp -d)"
trap 'kill "${SRV_PID:-}" 2>/dev/null || true; rm -rf "$DATA_DIR"' EXIT

"$BIN" serve --port 0 --bind 127.0.0.1 --data-dir "$DATA_DIR" >"$DATA_DIR/server.log" 2>&1 &
SRV_PID=$!

# Discover the chosen port from the "listening on ..." line.
PORT=""
for _ in $(seq 1 100); do
    PORT="$(sed -n 's/^listening on .*:\([0-9]*\)$/\1/p' "$DATA_DIR/server.log" | head -n1)"
    [ -n "$PORT" ] && break
    kill -0 "$SRV_PID" 2>/dev/null || { echo "daemon exited early:"; cat "$DATA_DIR/server.log"; exit 1; }
    sleep 0.1
done
[ -n "$PORT" ] || { echo "daemon did not report a listening port" >&2; exit 1; }

mkdir -p "$SEED/sha256"
for ref in "${IMAGES[@]}"; do
    digest="${ref##*@sha256:}"
    dest="$SEED/sha256/$digest"
    if [ -d "$dest/rootfs" ]; then
        echo "seed already present for $digest — skipping"
        continue
    fi
    echo "pulling $ref ..."
    id="$(curl -fsS -X POST "http://127.0.0.1:$PORT/v1/sandboxes" \
        -H 'Content-Type: application/json' \
        -d "{\"image\":{\"uri\":\"$ref\"},\"mounts\":[],\"network\":\"isolated\",\"env\":{}}" \
        | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')"
    [ -n "$id" ] || { echo "create did not return an id" >&2; exit 1; }

    # Provisioning (pull + extract) completes when the sandbox reaches stopped.
    for _ in $(seq 1 600); do
        state="$(curl -fsS "http://127.0.0.1:$PORT/v1/sandboxes/$id" \
            | sed -n 's/.*"state":"\([^"]*\)".*/\1/p')"
        [ "$state" = "stopped" ] && break
        [ "$state" = "failed" ] && { echo "provisioning failed for $digest" >&2; exit 1; }
        sleep 0.5
    done

    src="$DATA_DIR/images/sha256/$digest"
    [ -d "$src/rootfs" ] || { echo "expected cache entry not found at $src" >&2; exit 1; }
    cp -a "$src" "$dest"
    echo "seeded $dest"
done

echo "seed complete at $SEED"
