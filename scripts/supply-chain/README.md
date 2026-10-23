# Supply-chain checks

Users build every image on their own machine, so anything fetched at build time runs there. The `api`
image mounts the host Docker socket, so a compromised dependency in it is root on the user's host. This
directory holds the policy and the tools we use to vet versions before a release.

| File | sha256 |
|---|---|
| `sccheck.mjs`: version checker (OSV incl. MAL-\*, registry metadata, IOC list) | `f5e00dbf7d0170394377638aac9be47d8d806793acaa80fb9a2b7d61432bbf9e` |
| `pyhash.mjs`: hash-locked requirements from a pip report | `8f78bc1f29e71379094ad4f5caed74d32e55c47e7133742267faa5420801fb55` |

Both are zero-dependency Node scripts. They read public registry and OSV metadata and never install or
run a package. Each is the release-vetted copy (sccheck `e35af154…`, pyhash `165e703c…`) plus fail-closed
fixes; the hashes above are of the files as committed. `.gitattributes` keeps them LF on every checkout
(including Windows with `core.autocrlf=true`), so `sha256sum *.mjs` matches the table.

## Version policy

- **Direct targets** (package.json deps, go.mod requires, requirements pins, `FROM` images, tool tags,
  git SHAs, download URLs): published at least **14 days** before the release cut-off.
- **Transitive** (lockfile-resolved): at least **7 days** old. Enforce it while resolving
  (`npm --before`, `pip --uploaded-prior-to`), not after.
- **Exception** (a younger direct target): only when no older release fixes a high/critical
  vulnerability that affects us. It needs provenance or publisher continuity, a reviewed diff or release
  notes, and no compromise reports. Write the justification down.
- **Every adopted version**: no OSV/GHSA advisory that affects it (or a written reachability argument);
  no MAL-/IOC hit; not yanked or security-deprecated; no unexplained publisher change or dropped
  provenance; the canonical package name; no credible compromise reports.
- Prefer patch/minor over major. Take a major only when a fix needs it or the line is EOL.
- **Pinning**: base images `name:tag@sha256:<multi-arch index digest>`; git clones by full SHA that is
  on the canonical repo's history; downloads with a hardcoded sha256; pip hash-locked and installed with
  `--no-deps --require-hashes --only-binary=:all:`; npm a committed lock and `npm ci`; `go install` an
  exact version. apt/apk from the distro's signed repos is acceptable.
- Never use trivy, osv-scanner, snyk, grype or other scanner binaries, images or actions (scanners have
  been compromised themselves).

## Tooling

- **Node**: the current patch release of the active LTS line, installed from nodejs.org with its
  `SHASUMS256.txt` signature verified (the scripts need only Node >= 18).
- **govulncheck**: `go install golang.org/x/vuln/cmd/govulncheck@<version>`, built with a current Go
  patch release. It inherits the standard library of the Go that built it, so rebuild it after every Go
  upgrade.
- **pip**: a current release that passes the checker, used for resolution only. The hashes come from
  PyPI over Node's TLS (`pyhash.mjs`), `pyhash` fails if pip's chosen file is not among them, and images
  install with `--require-hashes`.

## Before each release

Set two cut-offs: `DIRECT` = release date minus 14 days, `TRANSITIVE` = minus 7 days (UTC,
`YYYY-MM-DDT00:00:00Z`). Delete `.sccache/` once so registry data is fresh. Run anything that
executes dependency code (npm ci with scripts, builds, tests, `pip install` of an sdist, imports) only in
a throwaway container with no Docker socket and no host secrets. Run `docker login` first (a read-only
Docker Hub token is enough): digest inspection and building ~57 images anonymously from one IP hits Hub's
pull limit (HTTP 429 `toomanyrequests`).

**npm** (resolution on the host runs no package code):
```
npm install --package-lock-only --ignore-scripts --before=<TRANSITIVE>
```
`min-release-age` and `--before` cannot be combined: npm 11.10/11.11 exit with "--min-release-age cannot
be provided when using --before", wherever the setting comes from (project `.npmrc`, `~/.npmrc` or
`npm_config_min_release_age`), and `--min-release-age=0`, `--no-min-release-age` or an empty value do not
get around it. `client/.npmrc` sets `min-release-age=7`, so in `client/` run the command without
`--before` and let `.npmrc` set the window. That window counts back from now, not from the cut-off, so
regenerate the client lock on the cut-off day. The other npm directories use `--before`. A
`min-release-age` in your user `~/.npmrc` also breaks the `npx --before=… mcp-remote` line in the
top-level README; for that command, run npx with `--userconfig` pointing at an empty file. Dockerfiles use
`npm ci --ignore-scripts`; `npm rebuild <pkg>` only for reviewed packages. Lifecycle `prepare` scripts
of registry packages do not run.

**pip** (resolve inside a container from a pinned Python image, then lock on the host):
```
pip install --dry-run --ignore-installed --only-binary=:all: --uploaded-prior-to=<TRANSITIVE> --report /out/report.json -r requirements.in
node pyhash.mjs --uploaded-prior-to <TRANSITIVE> --report report.json --out requirements.txt
```
A recorded exception younger than the cut-off is locked on its own with
`--pins` and its own `--uploaded-prior-to`. Install with
`pip install --no-deps --require-hashes --only-binary=:all: -r requirements.txt`, then `pip check`.
Never use `--extra-index-url`, `--trusted-host` or `PIP_NO_REQUIRE_HASHES`. List any sdist-only package
explicitly. Keep `requirements.in` out of the way of Dependabot (it is excluded in `dependabot.yml`;
otherwise Dependabot switches to pip-compile and rewrites the lock).

**Go**: build with `GOTOOLCHAIN=local GOFLAGS=-mod=readonly`; never set `GOSUMDB=off`, `GONOSUMDB`,
`GOPRIVATE` or `GOINSECURE`. Check `go list -m -u -retracted all`, then `govulncheck ./...` on the
source and `govulncheck -mode=binary <bin>` on built binaries.

**Cargo**: `cargo build --locked`. **Bundler**: `bundle config set frozen true`.

**Checker**, on every lock or pin list you change:
```
node sccheck.mjs --npm|--pip|--gomod|--cargo|--gemlock <input> --ioc <ioc.json> --min-age-days 7 [--baseline <previous input>] --out <f.json>
node sccheck.mjs --list <direct pins: "ecosystem name version" lines> --ioc <ioc.json> --min-age-days 14
```
Exit 2 means a known-malicious version; 1 means something needs a decision (see the flag list in the
script header); 0 means clean; 64 is a usage error (no mode, an option without a value or followed by
another `--option`, a `--min-age-days` that is not a number >= 0). Lookup failures (`NO_OSV`,
`NO_METADATA`, `NO_DATE`) fail the run. `--baseline` reports only new or changed entries, where a changed
tarball, hash or checksum counts as a change.

**Release gate**: `--baseline` is for reviewing a change. Before each release, run the checker once in
full, WITHOUT `--baseline`, on every final lock and pin list:
- the 4 npm locks (`client`, `docker/mcp-server`, `docker/session-keeper`, `docker/domdig`);
- `--gomod` on all 18 Go modules (`server`, `docker/<tool>`, every `docker/*/pin`,
  `docker/waybackurls/archivefetch`);
- `ai_service/requirements*.txt`, every `docker/*/requirements.txt` and `pip-bootstrap.txt`;
- `--cargo` on `docker/x8/Cargo.lock` and `docker/smugglex/Cargo.lock`;
- `--gemlock` on CeWL's upstream `Gemfile.lock` at the pinned SHA;
- the direct pins with `--list … --min-age-days 14`.

Every non-zero result must map to a written exception or it blocks the release. Record exceptions,
residuals and their reasons in `residuals.local.md` next to this file; it is gitignored and never
committed. Accepted results:
- `YOUNG` on a recorded exception;
- `NO_METADATA` on the torch `+cpu` local version;
- `GIT_SOURCE` on x8's raw-http fork crates: upstream declares them as bare git dependencies, so they are
  SHA-pinned in `docker/x8/Cargo.lock`, built `--locked`, and documented in `docker/x8/Dockerfile`;
- `VULN` on an advisory recorded as a residual, with its no-fix or reachability reason;
- `PUBLISHER_CHANGED` rows unchanged from the previous reviewed run. A new or changed row needs a review.

**Self-test** after changing either script (run it in a throwaway `node` container):
- Positive control: a `--list` of IOC versions (`npm debug 4.4.2`, `PyPI litellm 1.107.0`) with
  `--ioc` must exit 2.
- Dead network: `NODE_USE_ENV_PROXY=1 HTTPS_PROXY=http://127.0.0.1:9` must make both scripts exit
  non-zero, with a cold and with a warm `--cache`.
- Usage errors: `--min-age-days abc|-1|''|Infinity`, a trailing `--ioc` or `--out`, and
  `--ioc --min-age-days 7` must exit 64.
- pyhash with `--out` over an existing file and a bad `--pins` line (or a dead network) must exit 1 and
  leave that file unchanged.

What the checker does not see; check by hand for direct targets:
- GHSAs missing from OSV (repo-level advisories) and unreviewed GHSAs without a package mapping. Query
  `gh api '/advisories?affects=<pkg>'`, `gh api repos/<o>/<r>/security-advisories` and NVD by CVE.
- OSV ranges that end too early (an advisory whose range stops before the version you pin).
- Code bundled inside an npm tarball (not in the lock), and PyPI uploader continuity.
- Hashes of direct-URL wheels on download.pytorch.org (checked against PyPI only for files.pythonhosted.org).
- `DEPRECATED` and `INSTALL_SCRIPT` are reported but do not fail the run; read them.

**Base images**: `FROM name:tag@sha256:<index digest>` at column 0, no `${ARG}` image names, no unpinned
`# syntax=` line. Check with `docker buildx imagetools inspect name:tag`: the digest must be an index
covering linux/amd64 and linux/arm64, and its newest platform `created` must be before `DIRECT`. Refresh
digests by hand every release; Dependabot does not reliably propose same-tag digest refreshes.

**Git pins**: full 40-hex SHA, fetched by SHA, with
`test "$(git rev-parse HEAD)" = <SHA>` in the build. Before adopting one, confirm it is on the canonical
default branch: `gh api repos/<o>/<r>/compare/<SHA>...<branch>` must be `identical` or `ahead` with
`behind_by` 0 (a fork-network commit can be fetched by SHA from the canonical URL).

**Downloads**: `ADD --checksum=sha256:<hex> <url> <dest>` or `sha256sum -c` with a hash recorded at
review time. Never fetch a `checksums.txt` at build time (release assets are mutable).

**After the build**: in each Python image, fail on any `*.pth` other than `distutils-precedence.pth`,
any `sitecustomize.py`/`usercustomize.py`, or a known IOC file (LiteLLM-style payloads run at
interpreter start-up):
```
docker run --rm --network none --entrypoint python <image> -c "import site,glob,os;d=site.getsitepackages()+[site.getusersitepackages()];b=[f for p in d for f in glob.glob(os.path.join(p,'*.pth'))+glob.glob(os.path.join(p,'*customize.py')) if os.path.basename(f)!='distutils-precedence.pth'];print(b);raise SystemExit(bool(b))"
```
Build images one at a time with `build.sh`/`build.ps1`, not `docker compose up --build`.

## Dependabot

`.github/dependabot.yml` covers npm, gomod, pip, docker and docker-compose, with a 14-day cooldown (30
for semver-major on npm/gomod/pip), grouped PRs and open-PR limits. Before merging any Dependabot PR:
- Security-update PRs skip the cooldown (and npm's `min-release-age`): run the checker with
  `--min-age-days 14` on the bumped direct pin and 7 on the lock.
- pip PRs bump one line without re-resolving: re-lock with the pip steps above and run `pip check`.
- Dependabot cannot see: `go install <tool>@<version>`, git SHAs, curl/ADD downloads, inline
  `pip install`/`npm install -g` in Dockerfiles, apt/apk packages, nuclei-templates, the Chrome `.deb`,
  the extension's CDN stylesheets, and the `npx mcp-remote` line in the top-level README. Review those by
  hand each release.
- Refresh by hand (Dependabot cannot update these):
  - `docker/x8` and `docker/smugglex` `Cargo.lock`: there is no `Cargo.toml` here, and Dependabot's cargo
    support needs one. When the upstream SHA moves, regenerate the lock in a container from upstream at
    the pinned SHA, then run `--cargo` on it.
  - CeWL's `Gemfile.lock`: upstream's file at the pinned SHA, not in this repo. Run `--gemlock` on it
    whenever the SHA moves.
  - torch `+cpu` (`ai_service/requirements-torch.txt`): ignored in `dependabot.yml`, because Dependabot
    would propose PyPI's CUDA build with PyPI hashes. When a torch alert fires, re-lock it from
    `download.pytorch.org/whl/cpu`.
  - The extension's CDN stylesheets (`extension/popup.html`): they carry `integrity` (SRI). A version bump
    needs new sha384 values, computed from the files in the npm tarball (check the tarball's sha512
    against the registry's `dist.integrity`) and compared byte for byte with jsDelivr's copy.
