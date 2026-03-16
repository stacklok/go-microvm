// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"context"
	"fmt"
	"os"
)

// RunnerBinaryName is the expected filename for the go-microvm-runner binary
// within a runtime source directory.
const RunnerBinaryName = "go-microvm-runner"

// Source resolves a set of files into a directory, using cacheDir for
// extraction-based implementations. The context allows caller-implemented
// sources (e.g. downloaders) to respect cancellation.
type Source interface {
	Ensure(ctx context.Context, cacheDir string) (dir string, err error)
}

// Compile-time interface compliance checks.
var (
	_ Source = (*bundleSource)(nil)
	_ Source = (*dirSource)(nil)
)

// bundleSource wraps a Bundle as a Source. It delegates to Bundle.Ensure,
// validating that cacheDir is non-empty.
type bundleSource struct {
	bundle *Bundle
}

// Ensure extracts the bundle into cacheDir and returns the extraction directory.
func (s *bundleSource) Ensure(_ context.Context, cacheDir string) (string, error) {
	if cacheDir == "" {
		return "", fmt.Errorf("bundle source: cache directory must not be empty")
	}
	return s.bundle.Ensure(cacheDir)
}

// dirSource points to an existing directory on disk. It verifies the
// directory exists and returns its path, ignoring cacheDir.
type dirSource struct {
	path string
}

// Ensure verifies the directory exists and returns its path.
func (s *dirSource) Ensure(_ context.Context, _ string) (string, error) {
	info, err := os.Stat(s.path)
	if err != nil {
		return "", fmt.Errorf("dir source: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("dir source: %s is not a directory", s.path)
	}
	return s.path, nil
}

// RuntimeBundle creates a Source that extracts go-microvm-runner and libkrun
// into a versioned cache directory. The runner and libkrun byte slices are
// the file contents to extract. The libkrun major soname version is always 1
// because the runner binary is built against a specific libkrun ABI.
// Additional dylibs (e.g. libepoxy, virglrenderer, MoltenVK on macOS) can be
// passed via extraLibs and will be extracted alongside the core files.
func RuntimeBundle(version string, runner, libkrun []byte, extraLibs ...File) Source {
	files := []File{
		{Name: RunnerBinaryName, Content: runner, Mode: 0o755},
		{Name: LibName("krun", 1), Content: libkrun, Mode: 0o755},
	}
	files = append(files, extraLibs...)
	return &bundleSource{bundle: NewBundle(version, files)}
}

// FirmwareBundle creates a Source that extracts libkrunfw into a versioned
// cache directory. The major parameter is the soname major version number.
func FirmwareBundle(version string, major int, firmware []byte) Source {
	return &bundleSource{bundle: NewBundle(version, []File{
		{Name: LibName("krunfw", major), Content: firmware, Mode: 0o755},
	})}
}

// Dir creates a Source that points to an existing directory. It verifies
// the directory exists on each call and ignores cacheDir.
func Dir(path string) Source {
	return &dirSource{path: path}
}
