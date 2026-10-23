# Dalfox is published as an image already, so there is nothing to build. Pinned rather than :latest
# because the CLI changed shape between v2 and v3: v2 took `dalfox url <target>` and v3 takes
# `dalfox scan <target>`, and the runner emits v3 syntax. A floating tag that rolls back to v2, or
# forward to a v4 that renames the subcommand again, turns every scan into a usage error.
#
# Also pinned by digest, because a tag can be re-pushed and a digest cannot. v3.2.4 rather than
# v3.2.1: GHSA-mph2-gf5w-6f9f and GHSA-69jp-6fh7-wjpm (both HIGH, fixed in 3.2.3) let a scanned host
# receive the operator --cookies / -H values, which ComposeDalfox passes. Neither advisory is in OSV.
# The scan flags are identical between the two releases (diffed from --help).
FROM ghcr.io/hahwul/dalfox:v3.2.4@sha256:d932c680426d514634b4f4fc81803ccfba304c697afdb4e65082b2cf81084d3f

# The published image sets Cmd to ["./dalfox"] with no Entrypoint, so the binary is only on the
# relative path from its WORKDIR. `docker exec dalfox --help` would fail with "executable not found"
# because exec does not inherit Cmd. Symlinking it onto PATH is what makes `docker exec <container>
# dalfox scan ...` work the same way every other tool container in this framework does.
USER root
# apk upgrade pulls current signed Alpine fixes (zlib, musl) and the ca-certificates release that
# drops the compromised emSign ECC Root CA - G3; the build fails if that root is still trusted or the
# bundle is missing. The bundle holds PEM blocks with no names, so the check matches the
# certificate's first base64 line (grepping the CA name could never fail).
#
# That bundle is also dalfox's trust store. v3.2.4 verifies TLS through rustls-platform-verifier,
# which on Linux loads /etc/ssl/certs; the webpki-root-certs crate in its lock is not compiled in
# (none of its root names is in the binary). Scan targets are fetched with --insecure on by default,
# so this matters for the verified connections only, such as the interactsh OOB mesh.
RUN apk upgrade --no-cache \
    && test -s /etc/ssl/certs/ca-certificates.crt \
    && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt
RUN ln -sf "$(find / -maxdepth 4 -name dalfox -type f -perm -u+x 2>/dev/null | head -1)" /usr/local/bin/dalfox \
    && dalfox --version
# `dalfox --version`, not `dalfox version`. v3 defaults to the scan subcommand when the first
# argument is not one, so `dalfox version` tries to SCAN http://version/ and fails on DNS. The build
# check has to use the flag or it fails for a reason that has nothing to do with the install.

# Back to the upstream image's unprivileged user once the root-only steps are done, so a scanned
# host that found a way into dalfox lands as `app`, not root. Nothing at runtime needs root: compose
# runs `sleep infinity`, every `docker exec` then runs as app, and the server only reads and writes
# per-scan files under /tmp (the shared temp_data volume, mode 1777) and reads /app/wordlists.
USER app

ENTRYPOINT ["dalfox"]
