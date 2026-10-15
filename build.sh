#!/usr/bin/env sh
# Reliable first-time build for the Ars0n Framework.
#
# WHY THIS EXISTS. `docker compose up -d --build` builds every image in PARALLEL. On a cold cache
# that means ~17 source tools compiling at once, which fails two ways that have nothing to do with
# the code:
#   * CPU/network contention starves a heavy compile (x8's Rust build) until BuildKit's deadline
#     fires: "failed to solve: Internal: context deadline exceeded".
#   * Docker's containerd image store (the default since Docker Desktop 29) races when several
#     builds export/tag at the same time: 'image "...": already exists', or
#     'failed to prepare extraction snapshot ... parent snapshot does not exist' (which also leaves
#     the build cache corrupted).
# Building ONE service at a time removes both: nothing competes for resources, and no two image
# exports collide. It is slower than a parallel build, but it finishes, which is the point.
# NOTE: there is no Docker/Compose setting that bounds the parallel build here -- COMPOSE_PARALLEL_LIMIT
# throttles container create/start/pull, NOT the build phase (verified on Compose v2.40 / Docker 29).
# Serial, one `docker compose build <svc>` per service, is the only mechanism that actually works.
#
# Cached images are instant, so re-running this after a partial build only compiles what is missing.
# Each service gets up to 3 attempts; the first two are plain retries (for a transient registry/proxy
# hiccup), and the final attempt clears the build cache and rebuilds --no-cache so a corrupted or
# wedged cache is recovered rather than retried against. On success the stack is started with
# `docker compose up -d`.
#
# Usage:  ./build.sh
set -eu

compose() { docker compose "$@"; }

echo ">>> Building images sequentially (this avoids the parallel-build races; cached layers are instant)"
for svc in $(compose config --services); do
  attempt=1
  max=3
  while true; do
    if [ "$attempt" -ge "$max" ]; then
      # Final attempt. Attempts 1..N-1 reused the SAME build cache, and a plain retry against it
      # cannot recover the failures that corrupt or wedge the cache itself: a bad BuildKit snapshot
      # ("failed to prepare extraction snapshot ... parent snapshot does not exist"), a stuck solve
      # ("Internal: context deadline exceeded"), or a half-exported image ("image ... already
      # exists"). So on the last try we clear the build cache and compile this one service clean.
      printf '>>> [%s] build attempt %d (clearing build cache, rebuilding --no-cache)\n' "$svc" "$attempt"
      docker builder prune -f >/dev/null 2>&1 || true
      if compose build --no-cache "$svc"; then
        break
      fi
      echo "!!! [$svc] failed after $attempt attempts (including a pruned clean rebuild). See the error above." >&2
      echo "!!! If it mentions 'parent snapshot does not exist', the containerd image store is wedged:" >&2
      echo "!!! restart Docker Desktop, then re-run ./build.sh (built images are cached)." >&2
      exit 1
    fi
    printf '>>> [%s] build attempt %d\n' "$svc" "$attempt"
    if compose build "$svc"; then
      break
    fi
    attempt=$((attempt + 1))
    sleep 8
  done
done

echo ">>> All images built. Starting the stack..."
compose up -d
echo ">>> Done. Check status with: docker compose ps"
