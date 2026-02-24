# CI & Release Pipelines

propolis uses three GitHub Actions workflows. They form a dependency chain:
the **Builder** produces a container image that **CI** and **Release** consume.

## Workflows

### CI (`ci.yaml`)

Runs on every push to `main` and on pull requests. All jobs run in parallel.

**Pure Go jobs** (no CGO, exclude `krun` and `propolis-runner` packages):

| Job | Platform | What it does |
|-----|----------|-------------|
| Test | Linux | `go test -race` |
| Lint | Linux | golangci-lint |
| Build | Linux | `go build` (compilation check) |
| Test (macOS) | macOS ARM64 | `go test -race` |
| Lint (macOS) | macOS ARM64 | golangci-lint |
| Build (macOS) | macOS ARM64 | Pure Go build + CGO build with Homebrew libkrun + code signing |

**CGO job:**

| Job | Platform | What it does |
|-----|----------|-------------|
| Build (Linux CGO) | Linux | Builds CGO packages and the runner binary inside the builder container |

The Linux CGO job pulls the builder image tagged with the libkrun version
from `versions.env`. If the builder image doesn't exist for that version,
this job fails. This is expected when bumping versions -- push the version
bump, wait for the Builder workflow to finish, then re-run the failed job.

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
   arm64 on `ubuntu-24.04-arm`) -- no QEMU emulation
2. Pushes each image by digest
3. Merges digests into a multi-arch manifest tagged with the libkrun
   version (e.g., `v1.17.3`) and `latest`

The build takes ~20 minutes because it compiles a Linux kernel (libkrunfw).
Results are cached via GitHub Actions cache.

### Release (`release.yaml`)

Runs when a version tag (`v*`) is pushed.

**What it produces:**
1. **Runtime tarball** (Apache-2.0): `propolis-runner` + `libkrun.so.1`
2. **Firmware tarball** (GPL-2.0): `libkrunfw.so.5`

Both are built for amd64 and arm64 using the builder image.

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
2. Push to `main` -- this triggers both CI and Builder
3. CI's Linux CGO job will fail (image doesn't exist yet)
4. Wait for Builder to finish (~20 min)
5. Re-run the failed CI job

## Platform Differences

**Linux CGO builds** use the builder container, which provides pre-compiled
libkrun and libkrunfw. The container runs Go builds with `-buildvcs=false`
because the mounted source directory isn't trusted by git.

**macOS CGO builds** install libkrun via Homebrew (`brew tap slp/krun`)
and sign the runner binary with Hypervisor.framework entitlements.

**Pure Go jobs** on both platforms exclude the `krun` and `propolis-runner`
packages since those require CGO.
