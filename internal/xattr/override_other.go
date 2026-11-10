// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package xattr

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

var overrideCache sync.Map

// SetOverrideStat records POSIX ownership and mode metadata for path on
// non-Unix hosts using an NTFS Alternate Data Stream with an in-memory fallback.
func SetOverrideStat(path string, uid, gid int, mode os.FileMode) error {
	if mode&(os.ModeSymlink|os.ModeNamedPipe|os.ModeSocket|os.ModeDevice) != 0 {
		return nil
	}
	unixMode := goFileModeToPosix(mode)
	val := fmt.Sprintf("%d:%d:0%o", uid, gid, unixMode)
	return writeOverrideValue(path, val)
}

// SetOverrideStatFromPath sets the override_stat metadata by reading the
// file's existing override mode (if any) or current mode via Lstat.
func SetOverrideStatFromPath(path string, uid, gid int) error {
	info, err := os.Lstat(path)
	if err != nil {
		slog.Debug("lstat for override_stat failed", "path", path, "err", err)
		return nil
	}
	if _, _, existingMode, ok := GetOverrideStat(path); ok {
		val := fmt.Sprintf("%d:%d:0%o", uid, gid, uint32(existingMode))
		return writeOverrideValue(path, val)
	}
	return SetOverrideStat(path, uid, gid, info.Mode())
}

// CopyOverrideStat copies the override_stat metadata from src to dst.
func CopyOverrideStat(src, dst string) error {
	raw, ok := readOverrideRaw(src)
	if !ok {
		return nil
	}
	return writeOverrideValue(dst, raw)
}

// GetOverrideStat reads and parses the override_stat metadata on path.
func GetOverrideStat(path string) (int, int, int64, bool) {
	raw, ok := readOverrideRaw(path)
	if !ok {
		return 0, 0, 0, false
	}
	return ParseOverrideStat(raw)
}

func readOverrideRaw(path string) (string, bool) {
	if data, err := os.ReadFile(path + ":" + overrideKey); err == nil && len(data) > 0 {
		return string(data), true
	}
	if key, err := filepath.Abs(path); err == nil {
		if val, ok := overrideCache.Load(filepath.Clean(key)); ok {
			return val.(string), true
		}
	}
	return "", false
}

func writeOverrideValue(path, val string) (retErr error) {
	if key, err := filepath.Abs(path); err == nil {
		overrideCache.Store(filepath.Clean(key), val)
	}
	info, statErr := os.Lstat(path)
	if statErr != nil || info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	streamPath := path + ":" + overrideKey
	err := os.WriteFile(streamPath, []byte(val), 0o600)
	if err == nil || !os.IsPermission(err) || info.Mode()&0o200 != 0 {
		if err != nil {
			slog.Debug("write override_stat stream failed", "path", path, "err", err)
		}
		return nil
	}
	origMode := info.Mode().Perm()
	if chmodErr := os.Chmod(path, origMode|0o200); chmodErr != nil {
		slog.Debug("make override_stat target writable failed", "path", path, "err", chmodErr)
		return nil
	}
	defer func() {
		if restoreErr := os.Chmod(path, origMode); restoreErr != nil {
			retErr = fmt.Errorf("%w: %w", ErrPermissionRestore, restoreErr)
		}
	}()
	if writeErr := os.WriteFile(streamPath, []byte(val), 0o600); writeErr != nil {
		slog.Debug("write override_stat stream after chmod failed", "path", path, "err", writeErr)
	}
	return nil
}
