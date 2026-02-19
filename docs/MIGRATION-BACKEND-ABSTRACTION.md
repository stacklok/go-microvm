# Migration Guide: hypervisor.Backend Abstraction

This document covers the breaking changes introduced by the
`hypervisor.Backend` abstraction layer and how to migrate downstream
consumers.

## Breaking Changes

| Removed API | Replacement | Affected projects |
|---|---|---|
| `propolis.WithRunnerPath(p)` | `libkrun.WithRunnerPath(p)` passed to `libkrun.NewBackend()` | waggle, apiary, toolhive-appliance |
| `propolis.WithLibDir(d)` | `libkrun.WithLibDir(d)` passed to `libkrun.NewBackend()` | waggle, toolhive-appliance |
| `propolis.WithSpawner(s)` | `libkrun.WithSpawner(s)` passed to `libkrun.NewBackend()` | tests only |
| `propolis.VM.PID() int` | `propolis.VM.ID() string` | waggle, toolhive-appliance |

## New Imports

```go
import "github.com/stacklok/propolis/hypervisor/libkrun"
```

## Migration Examples

### waggle (`pkg/infra/vm/propolis.go`)

**Before:**
```go
if opts.RunnerPath != "" {
    propolisOpts = append(propolisOpts, propolis.WithRunnerPath(opts.RunnerPath))
}
if opts.LibDir != "" {
    propolisOpts = append(propolisOpts, propolis.WithLibDir(opts.LibDir))
}
slog.Info("microVM created", "pid", vm.PID())
```

**After:**
```go
import "github.com/stacklok/propolis/hypervisor/libkrun"

var backendOpts []libkrun.Option
if opts.RunnerPath != "" {
    backendOpts = append(backendOpts, libkrun.WithRunnerPath(opts.RunnerPath))
}
if opts.LibDir != "" {
    backendOpts = append(backendOpts, libkrun.WithLibDir(opts.LibDir))
}
propolisOpts = append(propolisOpts, propolis.WithBackend(libkrun.NewBackend(backendOpts...)))
slog.Info("microVM created", "id", vm.ID())
```

### apiary (`internal/infra/vm/runner.go`)

**Before:**
```go
if r.runnerPath != "" {
    opts = append(opts, propolis.WithRunnerPath(r.runnerPath))
}
```

**After:**
```go
import "github.com/stacklok/propolis/hypervisor/libkrun"

if r.runnerPath != "" {
    opts = append(opts, propolis.WithBackend(libkrun.NewBackend(
        libkrun.WithRunnerPath(r.runnerPath),
    )))
}
```

### toolhive-appliance (`internal/vm/libkrun/manager_cgo.go`)

**Before:**
```go
if runnerPath != "" {
    propolisOpts = append(propolisOpts, propolis.WithRunnerPath(runnerPath))
}
if libDir != "" {
    propolisOpts = append(propolisOpts, propolis.WithLibDir(libDir))
}
PID: vmInstance.PID(),
go m.reaperLoop(vmInstance.PID())
```

**After:**
```go
import (
    "strconv"
    "github.com/stacklok/propolis/hypervisor/libkrun"
)

var backendOpts []libkrun.Option
if runnerPath != "" {
    backendOpts = append(backendOpts, libkrun.WithRunnerPath(runnerPath))
}
if libDir != "" {
    backendOpts = append(backendOpts, libkrun.WithLibDir(libDir))
}
propolisOpts = append(propolisOpts, propolis.WithBackend(libkrun.NewBackend(backendOpts...)))

// For PID — parse ID string:
id := vmInstance.ID()
pid, _ := strconv.Atoi(id)
// Use pid for state and reaper loop
```

### Test code using `WithSpawner`

**Before:**
```go
spawner := &mockSpawner{proc: mockProc, err: nil}
opts := []propolis.Option{
    propolis.WithSpawner(spawner),
}
```

**After:**
```go
// Implement hypervisor.Backend directly for test mocks:
type mockBackend struct {
    handle hypervisor.VMHandle
    err    error
}

func (m *mockBackend) Name() string { return "mock" }
func (m *mockBackend) PrepareRootFS(_ context.Context, p string, _ hypervisor.InitConfig) (string, error) {
    return p, nil
}
func (m *mockBackend) Start(_ context.Context, _ hypervisor.VMConfig) (hypervisor.VMHandle, error) {
    return m.handle, m.err
}

opts := []propolis.Option{
    propolis.WithBackend(&mockBackend{handle: mockHandle}),
}
```
