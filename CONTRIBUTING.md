# Contributing to propolis

## Prerequisites

- **Go 1.26+**
- **[Task](https://taskfile.dev/)** -- `go install github.com/go-task/task/v3/cmd/task@latest`
- **golangci-lint** -- `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`
- **goimports** -- `go install golang.org/x/tools/cmd/goimports@latest`

For CGO builds (runner binary), you also need libkrun headers:

| Platform | Install |
|----------|---------|
| Fedora | `sudo dnf install libkrun-devel` |
| macOS | `brew tap slp/krun && brew install libkrun libkrunfw` |
| Any Linux | `task build-runner` (uses builder container, no system libkrun needed) |

## Development Workflow

```bash
# 1. Make your changes

# 2. Format and lint
task fmt
task lint

# 3. Run tests
task test-nocgo          # Pure Go packages (no libkrun needed)
task test                # All packages (requires libkrun-devel)

# 4. Build the runner (pick one)
task build-dev           # Linux with system libkrun-devel
task build-dev-darwin    # macOS with Homebrew libkrun (auto-signs)
task build-runner        # Linux via builder container (no system deps)
```

`task verify` runs fmt, lint, and test in sequence as a pre-push check.

## Task Reference

Run `task --list` for the full list. Key tasks for development:

| Task | What it does |
|------|-------------|
| `task test` | Run all tests with race detector |
| `task test-nocgo` | Run tests excluding CGO packages |
| `task lint` | Run golangci-lint |
| `task fmt` | go fmt + goimports |
| `task verify` | fmt + lint + test (pre-push check) |
| `task build-dev` | Build runner binary (Linux, requires libkrun-devel) |
| `task build-dev-darwin` | Build runner binary (macOS, requires Homebrew libkrun) |
| `task build-runner` | Build runner via builder container (no system deps) |
| `task build-nocgo` | Verify pure Go packages compile |
| `task clean` | Remove bin/, dist/, and coverage files |

## Code Conventions

- **SPDX headers** on every `.go` and `.yaml` file
- **`log/slog`** for logging (no `fmt.Println` or `log.Printf`)
- **Error wrapping**: `fmt.Errorf("context: %w", err)`
- **Table-driven tests** with testify
- **Functional options**: follow the `With*` pattern in `options.go`
- **CGO boundary**: only `krun/` and `runner/cmd/propolis-runner/` use CGO.
  Never import `krun` from other packages.

## Commit Guidelines

- Imperative mood, capitalized, no trailing period
- Limit subject line to 50 characters
- Stage specific files only (never `git add -A`)

## CI

CI runs automatically on push and PR. See [docs/CI.md](docs/CI.md) for
details on the pipeline structure and the builder image dependency chain.

The key thing to know: most CI jobs run pure Go tests and lint. The Linux
CGO build depends on a pre-built builder container image. If you're only
changing pure Go code, all jobs should pass without any special setup.
