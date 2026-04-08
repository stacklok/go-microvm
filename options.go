// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package microvm

import (
	"context"
	"os"
	"path/filepath"
	"syscall"

	"github.com/stacklok/go-microvm/hypervisor"
	"github.com/stacklok/go-microvm/image"
	"github.com/stacklok/go-microvm/net"
	"github.com/stacklok/go-microvm/net/firewall"
	"github.com/stacklok/go-microvm/preflight"
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
	// ReadOnly makes the mount read-only inside the guest. Enforcement is
	// guest-side via MS_RDONLY mount flags; libkrun does not currently
	// support host-side read-only virtiofs. A compromised guest kernel
	// could bypass this restriction.
	ReadOnly bool
	// OverrideUID, when > 0, causes go-microvm to set the
	// user.containers.override_stat xattr on every file and directory under
	// HostPath before the VM starts. This makes libkrun's virtiofs FUSE
	// server report the given UID/GID to the guest instead of the real
	// host values. Symlinks are skipped for safety.
	// A zero value means "no override." Since 0 is the zero value for int,
	// overriding to UID 0 (root) is not supported through this field.
	// Ignored for ReadOnly mounts.
	OverrideUID int
	// OverrideGID sets the group ID for the override_stat xattr.
	// When 0 and OverrideUID > 0, defaults to OverrideUID.
	OverrideGID int
}

// EgressPolicy restricts outbound VM traffic to specific DNS hostnames.
// When set, only connections to resolved IPs of allowed hosts are permitted.
// DNS queries for non-allowed hosts receive NXDOMAIN responses.
type EgressPolicy struct {
	AllowedHosts []EgressHost
}

// EgressHost defines a single hostname allowed for egress traffic.
type EgressHost struct {
	Name     string   // "api.github.com" or "*.docker.io"
	Ports    []uint16 // empty = all ports
	Protocol uint8    // 0 = default (TCP), 6 = TCP, 17 = UDP
}

// config holds all resolved VM configuration.
type config struct {
	name                  string
	cpus                  uint32
	memory                uint32 // MiB
	tmpSizeMiB            uint32 // /tmp tmpfs size in MiB; 0 = use guest default (256)
	ports                 []PortForward
	initOverride          []string
	rootfsPath            string // pre-built rootfs directory; skips OCI image pull when set
	rootfsHooks           []RootFSHook
	netProvider           net.Provider
	firewallRules         []firewall.Rule
	firewallDefaultAction firewall.Action
	preflight             preflight.Checker
	postBootHooks         []PostBootHook
	dataDir               string
	egressPolicy          *EgressPolicy
	virtioFS              []VirtioFSMount
	imageCache            *image.Cache
	externalCache         bool               // true when WithImageCache was called explicitly
	imageFetcher          image.ImageFetcher // nil = default local-then-remote fallback
	backend               hypervisor.Backend // nil = default libkrun backend
	logLevel              uint32             // libkrun log level (0=off, 5=trace)
	cleanDataDir          bool
	removeAll             func(string) error
	stat                  func(string) (os.FileInfo, error)
	killProcess           func(pid int, sig syscall.Signal) error
	processAlive          func(pid int) bool
}

func defaultConfig() *config {
	dataDir := defaultDataDir()
	return &config{
		name:        "microvm",
		cpus:        1,
		memory:      512,
		ports:       nil,
		netProvider: nil, // lazy-initialized in Run() if not set by WithNetProvider
		preflight:   preflight.Default(),
		imageCache:  image.NewCache(filepath.Join(dataDir, "cache")),
		dataDir:     dataDir,
		removeAll:   forceRemoveAll,
		stat:        os.Stat,
		killProcess: func(pid int, sig syscall.Signal) error { return syscall.Kill(pid, sig) },
		processAlive: func(pid int) bool {
			proc, err := os.FindProcess(pid)
			if err != nil {
				return false
			}
			return proc.Signal(syscall.Signal(0)) == nil
		},
	}
}

func defaultDataDir() string {
	if dir := os.Getenv("GO_MICROVM_DATA_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	return filepath.Join(home, ".config", "go-microvm")
}

func (c *config) buildNetConfig() net.Config {
	forwards := make([]net.PortForward, len(c.ports))
	for i, p := range c.ports {
		forwards[i] = net.PortForward{Host: p.Host, Guest: p.Guest}
	}
	cfg := net.Config{
		LogDir:                c.dataDir,
		Forwards:              forwards,
		FirewallRules:         c.firewallRules,
		FirewallDefaultAction: c.firewallDefaultAction,
	}
	if c.egressPolicy != nil {
		hosts := make([]net.EgressHost, len(c.egressPolicy.AllowedHosts))
		for i, h := range c.egressPolicy.AllowedHosts {
			hosts[i] = net.EgressHost{
				Name:     h.Name,
				Ports:    h.Ports,
				Protocol: h.Protocol,
			}
		}
		cfg.EgressPolicy = &net.EgressPolicy{AllowedHosts: hosts}
	}
	return cfg
}

// --- Option constructors ---

// WithName sets the VM name. Defaults to "microvm".
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

// WithNetProvider replaces the default in-process network provider.
func WithNetProvider(p net.Provider) Option {
	return optionFunc(func(c *config) { c.netProvider = p })
}

// WithFirewallRules adds firewall rules for the in-process network provider.
// Rules are evaluated first-match-wins. When rules are configured, a relay
// with frame-level filtering is inserted between the VM and the virtual
// network. Connection tracking is automatic: return traffic for allowed
// connections is permitted without explicit rules.
func WithFirewallRules(rules ...firewall.Rule) Option {
	return optionFunc(func(c *config) { c.firewallRules = append(c.firewallRules, rules...) })
}

// WithFirewallDefaultAction sets the default action when no firewall rule
// matches a packet. Defaults to Allow (zero value). Set to Deny for a
// default-deny policy where only explicitly allowed traffic passes.
func WithFirewallDefaultAction(action firewall.Action) Option {
	return optionFunc(func(c *config) { c.firewallDefaultAction = action })
}

// WithPreflightChecker replaces the entire preflight checker. Use this when
// the caller manages its own preflight logic and wants to skip the built-in
// defaults (KVM, port availability, disk space). Pass [preflight.NewEmpty]()
// to disable all microvm preflight checks.
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

// WithBackend sets the hypervisor backend used to prepare the rootfs and
// start the VM. When nil (default), the libkrun backend is used.
func WithBackend(b hypervisor.Backend) Option {
	return optionFunc(func(c *config) { c.backend = b })
}

// WithDataDir sets the base directory for VM state, caches, and logs.
// Defaults to ~/.config/go-microvm or $GO_MICROVM_DATA_DIR.
func WithDataDir(path string) Option {
	return optionFunc(func(c *config) {
		c.dataDir = path
		if !c.externalCache {
			c.imageCache = image.NewCache(filepath.Join(path, "cache"))
		}
	})
}

// WithCleanDataDir removes any existing data directory contents before boot.
// Use only when the data dir is VM-scoped; the image cache is preserved if it
// lives under the data dir.
func WithCleanDataDir() Option {
	return optionFunc(func(c *config) { c.cleanDataDir = true })
}

// WithEgressPolicy restricts outbound VM traffic to the specified hostnames.
// DNS queries for non-allowed hosts are answered with NXDOMAIN at the relay
// level. DNS responses for allowed hosts are snooped to learn their IPs,
// which become temporary firewall rules.
//
// When set, the firewall default action is forced to Deny (a warning is
// logged if it was explicitly set to Allow), and a hosted network provider
// is auto-created if none was configured.
func WithEgressPolicy(p EgressPolicy) Option {
	return optionFunc(func(c *config) { c.egressPolicy = &p })
}

// WithVirtioFS adds virtio-fs mounts that expose host directories to the guest.
func WithVirtioFS(mounts ...VirtioFSMount) Option {
	return optionFunc(func(c *config) { c.virtioFS = append(c.virtioFS, mounts...) })
}

// WithImageCache sets a custom image cache. When set, [WithDataDir] will not
// override the cache with a data-dir-relative default, regardless of option
// ordering.
func WithImageCache(cache *image.Cache) Option {
	return optionFunc(func(c *config) {
		c.imageCache = cache
		c.externalCache = true
	})
}

// WithImageFetcher sets a custom image fetcher for OCI image retrieval.
// When nil (default), a local-then-remote fallback fetcher is used that tries
// the Docker/Podman daemon first, then falls back to remote registry pull.
func WithImageFetcher(f image.ImageFetcher) Option {
	return optionFunc(func(c *config) { c.imageFetcher = f })
}

// WithLogLevel sets the libkrun log verbosity (0=off, 1=error, ..., 5=trace).
// Logs are written to vm.log in the data directory.
func WithLogLevel(level uint32) Option {
	return optionFunc(func(c *config) { c.logLevel = level })
}

// WithTmpSize sets the size of the /tmp tmpfs inside the guest VM in MiB.
// Defaults to 256 MiB when 0 or not set. The kernel enforces available
// memory as the upper bound; unreasonable values will cause a mount failure
// inside the guest.
// The value is written to /etc/go-microvm.json in the rootfs and read by
// the guest init before mounting filesystems.
func WithTmpSize(mib uint32) Option {
	return optionFunc(func(c *config) { c.tmpSizeMiB = mib })
}
