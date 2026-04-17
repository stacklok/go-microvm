// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsExpectedProcess_Self(t *testing.T) {
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get self executable: %v", err)
	}

	pid := os.Getpid()
	if !IsExpectedProcess(pid, selfExe) {
		t.Errorf("IsExpectedProcess(%d, %q) = false, want true", pid, selfExe)
	}
}

func TestIsExpectedProcess_SelfBaseNameFallback(t *testing.T) {
	// When expectedBinary is NOT absolute (just a bare name), the fallback
	// base-name comparison applies.
	pid := os.Getpid()

	selfExe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get self executable: %v", err)
	}
	baseName := filepath.Base(selfExe)
	if !IsExpectedProcess(pid, baseName) {
		t.Errorf("IsExpectedProcess with bare base name should match self")
	}
}

func TestIsExpectedProcess_AbsolutePathMismatch(t *testing.T) {
	// When expectedBinary IS absolute, a different directory with the same
	// base name must NOT match. This is the strengthened guarantee against
	// unrelated binaries with colliding base names.
	pid := os.Getpid()

	selfExe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get self executable: %v", err)
	}
	baseName := filepath.Base(selfExe)
	if IsExpectedProcess(pid, "/some/other/path/"+baseName) {
		t.Errorf("absolute path mismatch must not match even with same base name")
	}
}

func TestIsExpectedProcess_WrongBinary(t *testing.T) {
	pid := os.Getpid()
	if IsExpectedProcess(pid, "/usr/bin/definitely-not-this-binary") {
		t.Error("IsExpectedProcess should return false for wrong binary name")
	}
}

func TestIsExpectedProcess_NonExistentPID(t *testing.T) {
	if IsExpectedProcess(99999999, "/usr/bin/anything") {
		t.Error("IsExpectedProcess should return false for non-existent PID")
	}
}

func TestIsExpectedProcess_ZeroPID(t *testing.T) {
	if IsExpectedProcess(0, "/usr/bin/anything") {
		t.Error("IsExpectedProcess should return false for PID 0")
	}
}
