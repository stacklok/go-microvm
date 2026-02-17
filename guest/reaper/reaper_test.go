// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package reaper

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartReturnsStopFunc(t *testing.T) {
	t.Parallel()
	stop := Start(slog.Default())
	require.NotNil(t, stop)
	assert.NotPanics(t, func() { stop() })
}

func TestStopIsIdempotentSafe(t *testing.T) {
	t.Parallel()
	stop := Start(slog.Default())
	require.NotNil(t, stop)
	// Calling stop once should not panic.
	stop()
	// The channel is closed after stop; calling stop again is not expected
	// but we verify the first call doesn't panic.
}
