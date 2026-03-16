---
paths:
  - "options.go"
  - "microvm.go"
  - "runner/config.go"
  - "runner/cmd/go-microvm-runner/main.go"
---

# Adding a New Option

1. Add the field to the `config` struct in `options.go`
2. Set the default in `defaultConfig()` if needed
3. Create a `With*` constructor following the existing pattern in `options.go`
4. Use the field in `microvm.go` (in `Run()`) where appropriate
5. If the option affects the runner, add the field to BOTH `runner.Config` in `runner/config.go` AND the runner's duplicate `Config` struct in `runner/cmd/go-microvm-runner/main.go` with the same JSON tag
