// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package harden

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Set writes value to the sysctl identified by key. The key uses the
// standard dotted notation (e.g. "kernel.kptr_restrict") which is
// converted to the /proc/sys/ path (/proc/sys/kernel/kptr_restrict).
func Set(key, value string) error {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return fmt.Errorf("sysctl %s=%s: %w", key, value, err)
	}
	return nil
}

// kernelDefault is a single sysctl key-value pair with a human-readable
// reason for why it is set.
type kernelDefault struct {
	key    string
	value  string
	reason string
}

// defaults lists the recommended kernel sysctls for guest hardening.
var defaults = []kernelDefault{
	{
		key:    "kernel.kptr_restrict",
		value:  "2",
		reason: "hide kernel pointers from all users",
	},
	{
		key:    "kernel.dmesg_restrict",
		value:  "1",
		reason: "restrict dmesg to privileged users",
	},
	{
		key:    "kernel.unprivileged_bpf_disabled",
		value:  "1",
		reason: "disable unprivileged BPF",
	},
	{
		key:    "kernel.perf_event_paranoid",
		value:  "3",
		reason: "disallow all perf events for unprivileged users",
	},
	{
		key:    "kernel.yama.ptrace_scope",
		value:  "2",
		reason: "restrict ptrace to CAP_SYS_PTRACE holders",
	},
	{
		key:    "net.core.bpf_jit_harden",
		value:  "2",
		reason: "harden BPF JIT against spraying attacks",
	},
	{
		key:    "kernel.sysrq",
		value:  "0",
		reason: "disable magic SysRq key",
	},
}

// KernelDefaults applies recommended kernel sysctl hardening. Each
// setting is applied independently; failures are logged as warnings
// rather than aborting boot, because individual sysctls may not be
// available on all kernel versions.
func KernelDefaults(logger *slog.Logger) {
	for _, d := range defaults {
		logger.Info("applying sysctl", "key", d.key, "value", d.value, "reason", d.reason)
		if err := Set(d.key, d.value); err != nil {
			logger.Warn("sysctl failed", "key", d.key, "error", err)
		}
	}
}

// sysctlPath converts a dotted sysctl key to its /proc/sys/ path.
func sysctlPath(key string) string {
	return "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
}
