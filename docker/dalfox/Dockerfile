# Dalfox is published as an image already, so there is nothing to build. Pinned rather than :latest
# because the CLI changed shape between v2 and v3: v2 took `dalfox url <target>` and v3 takes
# `dalfox scan <target>`, and the runner emits v3 syntax. A floating tag that rolls back to v2, or
# forward to a v4 that renames the subcommand again, turns every scan into a usage error.
FROM ghcr.io/hahwul/dalfox:v3.2.1

# The published image sets Cmd to ["./dalfox"] with no Entrypoint, so the binary is only on the
# relative path from its WORKDIR. `docker exec dalfox --help` would fail with "executable not found"
# because exec does not inherit Cmd. Symlinking it onto PATH is what makes `docker exec <container>
# dalfox scan ...` work the same way every other tool container in this framework does.
USER root
RUN ln -sf "$(find / -maxdepth 4 -name dalfox -type f -perm -u+x 2>/dev/null | head -1)" /usr/local/bin/dalfox \
    && dalfox --version
# `dalfox --version`, not `dalfox version`. v3 defaults to the scan subcommand when the first
# argument is not one, so `dalfox version` tries to SCAN http://version/ and fails on DNS. The build
# check has to use the flag or it fails for a reason that has nothing to do with the install.

ENTRYPOINT ["dalfox"]
