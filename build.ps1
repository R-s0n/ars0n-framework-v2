# Reliable first-time build for the Ars0n Framework (Windows / PowerShell).
#
# WHY THIS EXISTS. `docker compose up -d --build` builds every image in PARALLEL. On a cold cache
# that means ~17 source tools compiling at once, which fails two ways that have nothing to do with
# the code:
#   * CPU/network contention starves a heavy compile (x8's Rust build) until BuildKit's deadline
#     fires: "failed to solve: Internal: context deadline exceeded".
#   * Docker's containerd image store (the default since Docker Desktop 29) races when several
#     builds export/tag at the same time: 'image "...": already exists'.
# Building ONE service at a time removes both. Cached images are instant, so re-running this after a
# partial build only compiles what is missing. Each service gets up to 3 attempts so a transient
# registry hiccup does not abort the whole run. On success the stack is started.
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
    while ($true) {
        Write-Host (">>> [{0}] build attempt {1}" -f $svc, $attempt)
        docker compose build $svc
        if ($LASTEXITCODE -eq 0) { break }
        if ($attempt -ge 3) {
            Write-Host ("!!! [{0}] failed after {1} attempts. Re-run .\build.ps1 to resume (built images are cached)." -f $svc, $attempt)
            exit 1
        }
        $attempt++
        Start-Sleep -Seconds 8
    }
}

Write-Host ">>> All images built. Starting the stack..."
docker compose up -d
if ($LASTEXITCODE -ne 0) { Write-Host "!!! 'docker compose up -d' failed; see output above."; exit 1 }
Write-Host ">>> Done. Check status with: docker compose ps"
