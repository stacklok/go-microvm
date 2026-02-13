// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package propolis

import (
	"context"
	"os"
	"path/filepath"

	"github.com/stacklok/propolis/image"
	"github.com/stacklok/propolis/net"
	"github.com/stacklok/propolis/preflight"
	"github.com/stacklok/propolis/runner"
)

// Option configures a VM. Use the With* functions to create options.
type Option interface {
	apply(*config)
}

type optionFunc func(*config)

func (f optionFunc) apply(c *config) { f(c) }

// RootFSHook modifies the extracted rootfs directory before VM boot.
// It receives the path to the rootfs and the parsed OCI image config.
type RootFSHook func(rootfsPath string, imgConfig *image.OCIConfig) error

// PostBootHook runs after the VM process is confirmed alive.
type PostBootHook func(ctx context.Context, vm *VM) error

// PortForward maps a host port to a guest port.
type PortForward struct {
	Host  uint16
	Guest uint16
}

// VirtioFSMount exposes a host directory to the guest via virtio-fs.
type VirtioFSMount struct {
	Tag      string
	HostPath string
}

// config holds all resolved VM configuration.
type config struct {
	name          string
	cpus          uint32
	memory        uint32 // MiB
	ports         []PortForward
	initOverride  []string
	rootfsPath    string // pre-built rootfs directory; skips OCI image pull when set
	rootfsHooks   []RootFSHook
	netProvider   net.Provider
	preflight     preflight.Checker
	postBootHooks []PostBootHook
	libDir        string
	dataDir       string
	runnerPath    string
	virtioFS      []VirtioFSMount
	imageCache    *image.Cache
	imageFetcher  image.ImageFetcher // nil = default CraneFetcher
	spawner       runner.Spawner     // nil = default runner.Spawn
}

func defaultConfig() *config {
	dataDir := defaultDataDir()
	return &config{
		name:        "propolis",
		cpus:        1,
		memory:      512,
		ports:       nil,
		netProvider: nil, // lazy-initialized in Run() if not set by WithNetProvider
		preflight:   preflight.Default(),
		imageCache:  image.NewCache(filepath.Join(dataDir, "cache")),
		dataDir:     dataDir,
	}
}

func defaultDataDir() string {
	if dir := os.Getenv("PROPOLIS_DATA_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	return filepath.Join(home, ".config", "propolis")
}

func (c *config) buildNetConfig() net.Config {
	forwards := make([]net.PortForward, len(c.ports))
	for i, p := range c.ports {
		forwards[i] = net.PortForward{Host: p.Host, Guest: p.Guest}
	}
	return net.Config{
		LogDir:   c.dataDir,
		Forwards: forwards,
	}
}

// --- Option constructors ---

// WithName sets the VM name. Defaults to "propolis".
func WithName(name string) Option {
	return optionFunc(func(c *config) { c.name = name })
}

// WithCPUs sets the number of virtual CPUs. Defaults to 1.
// Note: stock libkrunfw caps at 8 vCPUs.
func WithCPUs(n uint32) Option {
	return optionFunc(func(c *config) { c.cpus = n })
}

// WithMemory sets the VM memory in MiB. Defaults to 512.
func WithMemory(mib uint32) Option {
	return optionFunc(func(c *config) { c.memory = mib })
}

// WithPorts adds port forwards from host to guest.
func WithPorts(forwards ...PortForward) Option {
	return optionFunc(func(c *config) { c.ports = append(c.ports, forwards...) })
}

// WithInitOverride replaces the OCI image CMD/ENTRYPOINT with a custom command.
// This is how advanced users (e.g. toolhive-appliance) inject a custom init script.
func WithInitOverride(cmd ...string) Option {
	return optionFunc(func(c *config) { c.initOverride = cmd })
}

// WithRootFSPath uses a pre-built rootfs directory instead of pulling an OCI
// image. When set, the imageRef parameter to [Run] is ignored and image.Pull
// is skipped entirely. Rootfs hooks and krun config writing still run against
// the provided path.
func WithRootFSPath(path string) Option {
	return optionFunc(func(c *config) { c.rootfsPath = path })
}

// WithRootFSHook adds hooks that modify the extracted rootfs before VM boot.
// Hooks run in order after image extraction and before .krun_config.json is written.
func WithRootFSHook(hooks ...RootFSHook) Option {
	return optionFunc(func(c *config) { c.rootfsHooks = append(c.rootfsHooks, hooks...) })
}

// WithNetProvider replaces the default gvproxy network provider.
func WithNetProvider(p net.Provider) Option {
	return optionFunc(func(c *config) { c.netProvider = p })
}

// WithPreflightChecker replaces the entire preflight checker. Use this when
// the caller manages its own preflight logic and wants to skip the built-in
// defaults (KVM, port availability, disk space). Pass [preflight.NewEmpty]()
// to disable all propolis preflight checks.
func WithPreflightChecker(checker preflight.Checker) Option {
	return optionFunc(func(c *config) { c.preflight = checker })
}

// WithPreflightChecks adds additional preflight checks.
// These are appended to the built-in defaults (KVM, port availability).
func WithPreflightChecks(checks ...preflight.Check) Option {
	return optionFunc(func(c *config) {
		for _, check := range checks {
			c.preflight.Register(check)
		}
	})
}

// WithPostBoot adds hooks that run after the VM process is confirmed alive.
func WithPostBoot(hooks ...PostBootHook) Option {
	return optionFunc(func(c *config) { c.postBootHooks = append(c.postBootHooks, hooks...) })
}

// WithLibDir sets the path to a directory containing libkrun/libkrunfw shared
// libraries. The runner subprocess will use this via LD_LIBRARY_PATH.
// When empty (default), system libraries are used.
func WithLibDir(path string) Option {
	return optionFunc(func(c *config) { c.libDir = path })
}

// WithDataDir sets the base directory for VM state, caches, and logs.
// Defaults to ~/.config/propolis or $PROPOLIS_DATA_DIR.
func WithDataDir(path string) Option {
	return optionFunc(func(c *config) {
		c.dataDir = path
		c.imageCache = image.NewCache(filepath.Join(path, "cache"))
	})
}

// WithRunnerPath sets the path to the propolis-runner binary.
// When empty, the runner is found via $PATH or alongside the calling binary.
func WithRunnerPath(path string) Option {
	return optionFunc(func(c *config) { c.runnerPath = path })
}

// WithVirtioFS adds virtio-fs mounts that expose host directories to the guest.
func WithVirtioFS(mounts ...VirtioFSMount) Option {
	return optionFunc(func(c *config) { c.virtioFS = append(c.virtioFS, mounts...) })
}

// WithImageCache sets a custom image cache.
func WithImageCache(cache *image.Cache) Option {
	return optionFunc(func(c *config) { c.imageCache = cache })
}

// WithImageFetcher sets a custom image fetcher for OCI image retrieval.
// When nil (default), the standard crane-based fetcher is used.
func WithImageFetcher(f image.ImageFetcher) Option {
	return optionFunc(func(c *config) { c.imageFetcher = f })
}

// WithSpawner sets a custom spawner for the runner subprocess.
// When nil (default), the standard runner.Spawn is used.
func WithSpawner(s runner.Spawner) Option {
	return optionFunc(func(c *config) { c.spawner = s })
}
