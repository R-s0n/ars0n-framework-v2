#!/usr/bin/env sh
# Reliable first-time build for the Ars0n Framework.
#
# WHY THIS EXISTS. `docker compose up -d --build` builds every image in PARALLEL. On a cold cache
# that means ~17 source tools compiling at once, which fails two ways that have nothing to do with
# the code:
#   * CPU/network contention starves a heavy compile (x8's Rust build) until BuildKit's deadline
#     fires: "failed to solve: Internal: context deadline exceeded".
#   * Docker's containerd image store (the default since Docker Desktop 29) races when several
#     builds export/tag at the same time: 'image "...": already exists'.
# Building ONE service at a time removes both: nothing competes for resources, and no two image
# exports collide. It is slower than a parallel build, but it finishes, which is the point.
#
# Cached images are instant, so re-running this after a partial build only compiles what is missing.
# Each service gets up to 3 attempts so a transient registry/proxy hiccup does not abort the whole
# run. On success the stack is started with `docker compose up -d`.
#
# Usage:  ./build.sh
set -eu

compose() { docker compose "$@"; }

echo ">>> Building images sequentially (this avoids the parallel-build races; cached layers are instant)"
for svc in $(compose config --services); do
  attempt=1
  while true; do
    printf '>>> [%s] build attempt %d\n' "$svc" "$attempt"
    if compose build "$svc"; then
      break
    fi
    if [ "$attempt" -ge 3 ]; then
      echo "!!! [$svc] failed after $attempt attempts. Re-run ./build.sh to resume (built images are cached)." >&2
      exit 1
    fi
    attempt=$((attempt + 1))
    sleep 8
  done
done

echo ">>> All images built. Starting the stack..."
compose up -d
echo ">>> Done. Check status with: docker compose ps"
