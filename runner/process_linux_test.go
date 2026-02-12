// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runner

import (
	"os"
	"testing"
)

func TestIsExpectedProcess_Self(t *testing.T) {
	// Our own process should match our own executable.
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get self executable: %v", err)
	}

	pid := os.Getpid()
	if !isExpectedProcess(pid, selfExe) {
		t.Errorf("isExpectedProcess(%d, %q) = false, want true", pid, selfExe)
	}
}

func TestIsExpectedProcess_SelfBaseName(t *testing.T) {
	// Should match by base name even if full paths differ.
	pid := os.Getpid()

	selfExe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get self executable: %v", err)
	}
	baseName := selfExe[len(selfExe)-len("runner.test"):] // last component
	if !isExpectedProcess(pid, "/some/other/path/"+baseName) {
		t.Errorf("isExpectedProcess with different dir but same base name should return true")
	}
}

func TestIsExpectedProcess_WrongBinary(t *testing.T) {
	// Our process should NOT match a different binary name.
	pid := os.Getpid()
	if isExpectedProcess(pid, "/usr/bin/definitely-not-this-binary") {
		t.Error("isExpectedProcess should return false for wrong binary name")
	}
}

func TestIsExpectedProcess_NonExistentPID(t *testing.T) {
	// A PID that doesn't exist should return false.
	if isExpectedProcess(99999999, "/usr/bin/anything") {
		t.Error("isExpectedProcess should return false for non-existent PID")
	}
}

func TestIsExpectedProcess_ZeroPID(t *testing.T) {
	if isExpectedProcess(0, "/usr/bin/anything") {
		t.Error("isExpectedProcess should return false for PID 0")
	}
}
