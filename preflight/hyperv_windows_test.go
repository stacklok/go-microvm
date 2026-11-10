// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package preflight

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHyperVChecker(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		loadDLL  func() error
		findProc func() error
		want     string
	}{
		{name: "available", loadDLL: func() error { return nil }, findProc: func() error { return nil }},
		{name: "DLL unavailable", loadDLL: func() error { return errors.New("missing") }, findProc: func() error { return nil }, want: "load vmcompute.dll"},
		{name: "procedure unavailable", loadDLL: func() error { return nil }, findProc: func() error { return errors.New("missing") }, want: "HcsEnumerateComputeSystems"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			checker := &hypervChecker{loadDLL: test.loadDLL, findProc: test.findProc}
			err := checker.check(context.Background())
			if test.want == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.ErrorContains(t, err, test.want)
		})
	}
}

func TestRegisterPlatformChecksWindows(t *testing.T) {
	t.Parallel()

	checker := &checker{}
	registerPlatformChecks(checker)
	require.Len(t, checker.checks, 3)
	assert.Equal(t, "hyperv", checker.checks[0].Name)
	assert.True(t, checker.checks[0].Required)
	assert.Equal(t, "disk-space", checker.checks[1].Name)
	assert.False(t, checker.checks[1].Required)
	assert.Equal(t, "resources", checker.checks[2].Name)
	assert.False(t, checker.checks[2].Required)
}

func TestHypervisorCheckWindows(t *testing.T) {
	t.Parallel()

	check := HypervisorCheck()
	assert.Equal(t, "hyperv", check.Name)
	assert.Equal(t, "Verify Hyper-V Host Compute Service (vmcompute) is available", check.Description)
	assert.True(t, check.Required)
	assert.NotNil(t, check.Run)
}
