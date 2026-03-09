// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package preflight

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestChownCheck_Root(t *testing.T) {
	t.Parallel()

	c := &chownChecker{
		getuid: func() int { return 0 },
		capget: func() (uint32, error) {
			t.Fatal("capget should not be called for root")
			return 0, nil
		},
	}

	err := c.check(context.Background())
	assert.NoError(t, err)
}

func TestChownCheck_HasCAP_CHOWN(t *testing.T) {
	t.Parallel()

	c := &chownChecker{
		getuid: func() int { return 1000 },
		capget: func() (uint32, error) {
			return 1 << unix.CAP_CHOWN, nil
		},
	}

	err := c.check(context.Background())
	assert.NoError(t, err)
}

func TestChownCheck_HasMultipleCaps(t *testing.T) {
	t.Parallel()

	c := &chownChecker{
		getuid: func() int { return 1000 },
		capget: func() (uint32, error) {
			return (1 << unix.CAP_CHOWN) | (1 << unix.CAP_DAC_OVERRIDE), nil
		},
	}

	err := c.check(context.Background())
	assert.NoError(t, err)
}

func TestChownCheck_NoCAP_CHOWN(t *testing.T) {
	t.Parallel()

	c := &chownChecker{
		getuid: func() int { return 1000 },
		capget: func() (uint32, error) {
			// Has other caps but not CAP_CHOWN.
			return 1 << unix.CAP_DAC_OVERRIDE, nil
		},
	}

	err := c.check(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CAP_CHOWN")
	assert.Contains(t, err.Error(), "permission errors")
}

func TestChownCheck_NoCaps(t *testing.T) {
	t.Parallel()

	c := &chownChecker{
		getuid: func() int { return 1000 },
		capget: func() (uint32, error) {
			return 0, nil
		},
	}

	err := c.check(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CAP_CHOWN")
}

func TestChownCheck_CapgetError(t *testing.T) {
	t.Parallel()

	c := &chownChecker{
		getuid: func() int { return 1000 },
		capget: func() (uint32, error) {
			return 0, fmt.Errorf("capget failed")
		},
	}

	err := c.check(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot read effective capabilities")
}
