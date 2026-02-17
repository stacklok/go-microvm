// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package harden

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCapLastCap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    uintptr
		wantErr bool
	}{
		{
			name:    "typical value",
			content: "40\n",
			want:    40,
		},
		{
			name:    "higher kernel",
			content: "41\n",
			want:    41,
		},
		{
			name:    "no trailing newline",
			content: "40",
			want:    40,
		},
		{
			name:    "whitespace padding",
			content: "  40  \n",
			want:    40,
		},
		{
			name:    "non-numeric",
			content: "abc\n",
			wantErr: true,
		},
		{
			name:    "empty",
			content: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseCapLastCapForTest(tt.content)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestKeepSetContains(t *testing.T) {
	t.Parallel()

	keep := []uintptr{CapSetUID, CapSetGID, CapNetBindService}

	tests := []struct {
		name string
		cap  uintptr
		want bool
	}{
		{name: "CAP_SETUID in set", cap: CapSetUID, want: true},
		{name: "CAP_SETGID in set", cap: CapSetGID, want: true},
		{name: "CAP_NET_BIND_SERVICE in set", cap: CapNetBindService, want: true},
		{name: "CAP_CHOWN not in set", cap: CapChown, want: false},
		{name: "CAP_KILL not in set", cap: CapKill, want: false},
		{name: "arbitrary cap not in set", cap: 99, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, KeepSetContainsForTest(keep, tt.cap))
		})
	}
}

func TestKeepSetContains_EmptySet(t *testing.T) {
	t.Parallel()

	// With an empty keep set, nothing should be kept.
	assert.False(t, KeepSetContainsForTest(nil, CapSetUID))
	assert.False(t, KeepSetContainsForTest([]uintptr{}, CapSetGID))
}

func TestCapConstants(t *testing.T) {
	t.Parallel()

	// Verify the capability constants match Linux kernel values.
	assert.Equal(t, uintptr(0), CapChown)
	assert.Equal(t, uintptr(5), CapKill)
	assert.Equal(t, uintptr(6), CapSetGID)
	assert.Equal(t, uintptr(7), CapSetUID)
	assert.Equal(t, uintptr(10), CapNetBindService)
}

func TestCapLastCap_ReadsProc(t *testing.T) {
	t.Parallel()

	// capLastCap should return a reasonable value from /proc or the
	// fallback. On any Linux system the value should be >= 0.
	got := capLastCap()
	assert.GreaterOrEqual(t, got, uintptr(0))
	// Modern kernels have at least 40 capabilities.
	assert.GreaterOrEqual(t, got, uintptr(36))
}

func TestSetNoNewPrivs(t *testing.T) {
	t.Parallel()

	// SetNoNewPrivs is safe to call in tests — it only affects the
	// current process and is non-reversible but harmless.
	err := SetNoNewPrivs()
	require.NoError(t, err)
}
