// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/stacklok/propolis/image"
	"github.com/stacklok/propolis/internal/pathutil"
)

// validEnvKey matches POSIX-compliant environment variable names.
var validEnvKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// KeyOption configures InjectAuthorizedKeys.
type KeyOption interface {
	apply(*keyConfig)
}

type keyOptionFunc func(*keyConfig)

func (f keyOptionFunc) apply(c *keyConfig) { f(c) }

// ChownFunc abstracts file ownership changes for testability.
// Production code uses BestEffortLchown; tests can pass a recording mock.
type ChownFunc func(path string, uid, gid int) error

type keyConfig struct {
	home  string
	uid   int
	gid   int
	chown ChownFunc
}

func defaultKeyConfig() *keyConfig {
	return &keyConfig{home: "/home/sandbox", uid: 1000, gid: 1000, chown: BestEffortLchown}
}

// WithKeyUser overrides the default user home, UID, and GID for SSH key injection.
func WithKeyUser(home string, uid, gid int) KeyOption {
	return keyOptionFunc(func(c *keyConfig) { c.home = home; c.uid = uid; c.gid = gid })
}

// WithChown overrides the chown function used by InjectAuthorizedKeys.
// Useful for testing or environments where chown must be handled differently.
func WithChown(fn ChownFunc) KeyOption {
	return keyOptionFunc(func(c *keyConfig) { c.chown = fn })
}

// InjectAuthorizedKeys returns a RootFSHook that writes the given public key
// to {home}/.ssh/authorized_keys inside the rootfs. The .ssh directory is
// created with 0700 permissions and the authorized_keys file with 0600.
// Both are chowned to the configured UID/GID (default 1000:1000).
func InjectAuthorizedKeys(pubKey string, opts ...KeyOption) func(string, *image.OCIConfig) error {
	return func(rootfsPath string, _ *image.OCIConfig) error {
		cfg := defaultKeyConfig()
		for _, o := range opts {
			o.apply(cfg)
		}

		sshDirGuest := cfg.home + "/.ssh"
		sshDir, err := pathutil.Contains(rootfsPath, sshDirGuest)
		if err != nil {
			return fmt.Errorf("validate .ssh path: %w", err)
		}
		if err := os.MkdirAll(sshDir, 0o700); err != nil {
			return fmt.Errorf("create .ssh dir: %w", err)
		}
		if err := cfg.chown(sshDir, cfg.uid, cfg.gid); err != nil {
			return fmt.Errorf("chown .ssh dir: %w", err)
		}

		akGuest := sshDirGuest + "/authorized_keys"
		akPath, err := pathutil.Contains(rootfsPath, akGuest)
		if err != nil {
			return fmt.Errorf("validate authorized_keys path: %w", err)
		}
		if err := os.WriteFile(akPath, []byte(pubKey+"\n"), 0o600); err != nil {
			return fmt.Errorf("write authorized_keys: %w", err)
		}
		if err := cfg.chown(akPath, cfg.uid, cfg.gid); err != nil {
			return fmt.Errorf("chown authorized_keys: %w", err)
		}

		return nil
	}
}

// InjectFile returns a RootFSHook that writes content to the specified guest
// path inside the rootfs with the given permissions. Parent directories are
// created as needed.
func InjectFile(guestPath string, content []byte, perm os.FileMode) func(string, *image.OCIConfig) error {
	return func(rootfsPath string, _ *image.OCIConfig) error {
		dst, err := pathutil.Contains(rootfsPath, guestPath)
		if err != nil {
			return fmt.Errorf("validate path %s: %w", guestPath, err)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return fmt.Errorf("create parent dirs for %s: %w", guestPath, err)
		}
		if err := os.WriteFile(dst, content, perm); err != nil {
			return fmt.Errorf("write %s: %w", guestPath, err)
		}
		return nil
	}
}

// InjectBinary returns a RootFSHook that writes binary data to the specified
// guest path with executable permissions (0755).
func InjectBinary(guestPath string, data []byte) func(string, *image.OCIConfig) error {
	return InjectFile(guestPath, data, 0o755)
}

// InjectEnvFile returns a RootFSHook that writes a shell-sourceable
// environment file to the specified guest path. Each entry is written as
// "export KEY=<shell-escaped-value>\n". The file is created with 0600
// permissions. If envMap is empty, the hook is a no-op.
func InjectEnvFile(guestPath string, envMap map[string]string) func(string, *image.OCIConfig) error {
	return func(rootfsPath string, _ *image.OCIConfig) error {
		if len(envMap) == 0 {
			return nil
		}

		// Validate all keys are safe POSIX identifiers before writing.
		for k := range envMap {
			if !validEnvKey.MatchString(k) {
				return fmt.Errorf("invalid environment variable name: %q", k)
			}
		}

		// Sort keys for deterministic output.
		keys := make([]string, 0, len(envMap))
		for k := range envMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var buf strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&buf, "export %s=%s\n", k, shellEscape(envMap[k]))
		}

		dst, err := pathutil.Contains(rootfsPath, guestPath)
		if err != nil {
			return fmt.Errorf("validate path %s: %w", guestPath, err)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return fmt.Errorf("create parent dirs for %s: %w", guestPath, err)
		}
		if err := os.WriteFile(dst, []byte(buf.String()), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", guestPath, err)
		}
		return nil
	}
}

// shellEscape wraps a value in single quotes for safe shell sourcing.
// Internal single quotes are escaped with the '\” idiom.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// BestEffortLchown attempts os.Lchown and silently ignores permission errors,
// returning nil. On macOS non-root users cannot chown to a different UID;
// the guest init will fix ownership at boot time. Non-permission errors are
// logged at warn level and also swallowed. Callers that need strict chown
// should call os.Lchown directly instead.
// Lchown is used instead of Chown to avoid following symlinks in the rootfs.
func BestEffortLchown(path string, uid, gid int) error {
	if err := os.Lchown(path, uid, gid); err != nil {
		if !os.IsPermission(err) {
			slog.Warn("lchown failed", "path", path, "uid", uid, "gid", gid, "err", err)
		}
	}
	return nil
}
