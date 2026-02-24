# CI & Release Pipelines

propolis uses three GitHub Actions workflows. They form a dependency chain:
the **Builder** produces a container image that **CI** and **Release** consume.

## Workflows

### CI (`ci.yaml`)

Runs on every push to `main` and on pull requests. All jobs run in parallel.

**Cross-platform jobs** (matrix: Linux + macOS, pure Go only):

| Job | What it does |
|-----|-------------|
| Test | `task test-nocgo` — tests with race detector, excluding CGO packages |
| Lint | golangci-lint with `CGO_ENABLED=0` |

**Linux-only jobs:**

| Job | What it does |
|-----|-------------|
| Build | `task build-nocgo` — compilation check for pure Go packages |
| Build (Linux CGO) | `task build-runner` — full runner build inside the builder container |

**macOS-only jobs:**

| Job | What it does |
|-----|-------------|
| Build (macOS CGO) | Installs Homebrew libkrun, runs `task build-dev-darwin` (build + code sign) |

All build logic lives in the Taskfile. Workflows only orchestrate (checkout,
setup tools, call task).

### Builder (`builder.yaml`)

Builds the `ghcr.io/stacklok/propolis-builder` container image, which
compiles libkrun and libkrunfw from source. This image provides the CGO
toolchain that CI and Release need.

**Triggers:**
- Push to `main` that changes `images/builder/**` or `versions.env`
- Version tags (`v*`)
- Manual dispatch

**How it works:**
1. Builds per-architecture images natively (amd64 on `ubuntu-latest`,
   arm64 on `ubuntu-24.04-arm`) — no QEMU emulation
2. Pushes each image by digest
3. Merges digests into a multi-arch manifest tagged with the libkrun
   version (e.g., `v1.17.3`) and `latest`

The build takes ~20 minutes because it compiles a Linux kernel (libkrunfw).
Results are cached via GitHub Actions cache.

### Release (`release.yaml`)

Runs when a version tag (`v*`) is pushed.

**How it works:**
1. `task build-runner` — builds the runner binary and extracts libraries
2. `task package-runtime` — creates runtime tarball (runner + libkrun, Apache-2.0)
3. `task package-firmware` — creates firmware tarball (libkrunfw, GPL-2.0)

Both architectures (amd64, arm64) build on native runners.

**Where artifacts go:**
- GitHub Release with checksums
- OCI artifacts pushed to `ghcr.io/stacklok/propolis/{runtime,firmware}`

The runtime and firmware are split into separate tarballs because they
have different licenses.

## Dependency Chain

```
versions.env ──► Builder Image ──► CI (Linux CGO job)
                      │
                      └──────────► Release (build + package)
```

When bumping libkrun/libkrunfw versions:

1. Update `versions.env` and `images/builder/Containerfile`
2. Push to `main` — this triggers both CI and Builder
3. CI's Linux CGO job will fail (image doesn't exist yet)
4. Wait for Builder to finish (~20 min)
5. Re-run the failed CI job

## Taskfile as Single Source of Truth

All build logic lives in `Taskfile.yaml`. The container runtime is
auto-detected (`podman` locally on Fedora/Silverblue, `docker` in CI).

Key tasks used by CI/Release:

| Task | Used by | Purpose |
|------|---------|---------|
| `test-nocgo` | CI | Tests excluding CGO packages |
| `build-nocgo` | CI | Compilation check for pure Go |
| `build-runner` | CI, Release | Full runner build in builder container |
| `build-dev-darwin` | CI | macOS native build + code sign |
| `package-runtime` | Release | Runtime tarball (Apache-2.0) |
| `package-firmware` | Release | Firmware tarball (GPL-2.0) |

Container-based builds use `-buildvcs=false` because Docker-mounted source
directories aren't trusted by git. This is fine because version info is
set explicitly via ldflags.
