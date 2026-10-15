# Reliable first-time build for the Ars0n Framework (Windows / PowerShell).
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
# Building ONE service at a time removes both. There is no Docker/Compose setting that bounds the
# parallel build here -- COMPOSE_PARALLEL_LIMIT throttles container create/start/pull, NOT the build
# phase (verified on Compose v2.40 / Docker 29); serial builds are the only mechanism that works.
# Cached images are instant, so re-running this after a partial build only compiles what is missing.
# Each service gets up to 3 attempts; the first two are plain retries (transient registry hiccup), and
# the final attempt clears the build cache and rebuilds --no-cache so a corrupted or wedged cache is
# recovered rather than retried against. On success the stack is started.
#
# Usage:  .\build.ps1
#
# Note: $ErrorActionPreference is deliberately NOT 'Stop' because `docker compose build` writes its
# progress to stderr, which PowerShell 5.1 would otherwise treat as a terminating error. Success is
# judged by $LASTEXITCODE instead.

$services = docker compose config --services
if ($LASTEXITCODE -ne 0) {
    Write-Host "Could not read services from docker-compose.yml. Run this from the folder that contains it."
    exit 1
}

Write-Host ">>> Building images sequentially (avoids the parallel-build races; cached layers are instant)"
foreach ($svc in $services) {
    $attempt = 1
    $max = 3
    while ($true) {
        if ($attempt -ge $max) {
            # Final attempt. Earlier attempts reused the SAME build cache, and a plain retry against it
            # cannot recover the failures that corrupt or wedge the cache itself: a bad BuildKit snapshot
            # ("parent snapshot does not exist"), a stuck solve ("context deadline exceeded"), or a
            # half-exported image ("image ... already exists"). So on the last try we clear the build
            # cache and compile this one service clean.
            Write-Host (">>> [{0}] build attempt {1} (clearing build cache, rebuilding --no-cache)" -f $svc, $attempt)
            docker builder prune -f | Out-Null
            docker compose build --no-cache $svc
            if ($LASTEXITCODE -eq 0) { break }
            Write-Host ("!!! [{0}] failed after {1} attempts (including a pruned clean rebuild). See the error above." -f $svc, $attempt)
            Write-Host "!!! If it mentions 'parent snapshot does not exist', the containerd image store is wedged:"
            Write-Host "!!! restart Docker Desktop, then re-run .\build.ps1 (built images are cached)."
            exit 1
        }
        Write-Host (">>> [{0}] build attempt {1}" -f $svc, $attempt)
        docker compose build $svc
        if ($LASTEXITCODE -eq 0) { break }
        $attempt++
        Start-Sleep -Seconds 8
    }
}

Write-Host ">>> All images built. Starting the stack..."
docker compose up -d
if ($LASTEXITCODE -ne 0) { Write-Host "!!! 'docker compose up -d' failed; see output above."; exit 1 }
Write-Host ">>> Done. Check status with: docker compose ps"
