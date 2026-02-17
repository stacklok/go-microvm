// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package pathutil

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Contains validates that guestPath resolves within rootDir and returns
// the cleaned absolute path. Leading slashes are stripped so that
// absolute guest paths (e.g. "/etc/passwd") are treated as relative to
// rootDir. It rejects ".." components that would escape rootDir.
func Contains(rootDir, guestPath string) (string, error) {
	// Strip leading slashes — guest paths are absolute within the guest
	// but relative to rootDir on the host.
	cleaned := filepath.Clean(guestPath)
	cleaned = strings.TrimPrefix(cleaned, string(filepath.Separator))

	// After cleaning, an empty path or bare "." is the root itself.
	if cleaned == "." || cleaned == "" {
		return filepath.Clean(rootDir), nil
	}

	target := filepath.Join(rootDir, cleaned)

	rel, err := filepath.Rel(rootDir, target)
	if err != nil {
		return "", fmt.Errorf("compute relative path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path traversal detected: %q resolves outside root", guestPath)
	}

	return target, nil
}
