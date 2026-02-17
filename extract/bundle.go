// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/gofrs/flock"
)

// File describes a single file to extract.
type File struct {
	Name    string
	Content []byte
	Mode    os.FileMode
}

// Symlink describes a symbolic link to create after extraction.
type Symlink struct {
	Target string // e.g. "libkrun.so.1"
	Name   string // e.g. "libkrun.so"
}

// Bundle holds files and symlinks to extract into a versioned cache directory.
type Bundle struct {
	version string
	files   []File
	links   []Symlink
	mu      sync.Mutex
}

// NewBundle creates a bundle with the given version string, files, and optional symlinks.
func NewBundle(version string, files []File, links ...Symlink) *Bundle {
	return &Bundle{version: version, files: files, links: links}
}

// Ensure extracts the bundle into a versioned subdirectory of cacheDir.
// It returns the path to the directory containing the extracted files.
// Extraction is skipped if a matching version already exists (cache hit).
// Concurrent and cross-process safety is provided via in-process mutex
// and cross-process file locking.
func (b *Bundle) Ensure(cacheDir string) (string, error) {
	hash := b.computeHash()
	targetDir := filepath.Join(cacheDir, "extract-"+hash[:16])

	// Fast path: check if already extracted.
	if b.isValid(targetDir, hash) {
		return targetDir, nil
	}

	// Acquire in-process mutex.
	b.mu.Lock()
	defer b.mu.Unlock()

	// Acquire cross-process file lock.
	lockPath := filepath.Join(cacheDir, ".extract.lock")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("create cache dir: %w", err)
	}
	fl := flock.New(lockPath)
	if err := fl.Lock(); err != nil {
		return "", fmt.Errorf("acquire file lock: %w", err)
	}
	defer fl.Unlock() //nolint:errcheck // best-effort unlock

	// Double-check after acquiring lock.
	if b.isValid(targetDir, hash) {
		return targetDir, nil
	}

	// Create temp dir in cacheDir for atomic swap.
	tmpDir, err := os.MkdirTemp(cacheDir, "extract-tmp-")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	// Clean up temp dir on failure.
	defer func() {
		if err != nil {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	// Extract all files.
	for _, f := range b.files {
		if extractErr := b.extractFile(tmpDir, f); extractErr != nil {
			err = extractErr
			return "", fmt.Errorf("extract %s: %w", f.Name, extractErr)
		}
	}

	// Create symlinks.
	for _, l := range b.links {
		if linkErr := b.createSymlink(tmpDir, l); linkErr != nil {
			err = linkErr
			return "", fmt.Errorf("create symlink %s: %w", l.Name, linkErr)
		}
	}

	// Write version file.
	versionPath := filepath.Join(tmpDir, ".version")
	if writeErr := os.WriteFile(versionPath, []byte(hash), 0o644); writeErr != nil {
		err = writeErr
		return "", fmt.Errorf("write version file: %w", writeErr)
	}

	// Atomic rename to target.
	if renameErr := os.Rename(tmpDir, targetDir); renameErr != nil {
		err = renameErr
		return "", fmt.Errorf("rename to target: %w", renameErr)
	}

	return targetDir, nil
}

// computeHash returns a SHA-256 hex digest of the version string and all
// file contents.
func (b *Bundle) computeHash() string {
	h := sha256.New()
	h.Write([]byte(b.version))
	for _, f := range b.files {
		h.Write([]byte(f.Name))
		h.Write(f.Content)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// isValid checks whether targetDir exists and contains a .version file
// matching the expected hash.
func (b *Bundle) isValid(targetDir, hash string) bool {
	data, err := os.ReadFile(filepath.Join(targetDir, ".version"))
	if err != nil {
		return false
	}
	return string(data) == hash
}

// extractFile writes a single file atomically via a temp file and rename.
func (b *Bundle) extractFile(dir string, f File) error {
	dst := filepath.Join(dir, f.Name)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("create parent dirs: %w", err)
	}

	// Write to temp file first, then rename for atomicity.
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".tmp-"+filepath.Base(f.Name)+"-")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(f.Content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write content: %w", err)
	}
	if err := tmp.Chmod(f.Mode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("chmod: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename to final: %w", err)
	}
	return nil
}

// createSymlink creates a symbolic link in the given directory.
func (b *Bundle) createSymlink(dir string, l Symlink) error {
	linkPath := filepath.Join(dir, l.Name)
	if err := os.Symlink(l.Target, linkPath); err != nil {
		return fmt.Errorf("symlink %s -> %s: %w", l.Name, l.Target, err)
	}
	return nil
}
