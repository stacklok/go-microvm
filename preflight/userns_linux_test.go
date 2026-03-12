// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package preflight

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUsernsCheck_Root(t *testing.T) {
	t.Parallel()

	c := &usernsChecker{
		getuid: func() int { return 0 },
		readFile: func(_ string) ([]byte, error) {
			t.Fatal("readFile should not be called for root")
			return nil, nil
		},
	}

	err := c.check(context.Background())
	assert.NoError(t, err)
}

func TestUsernsCheck_SysctlNotExist(t *testing.T) {
	t.Parallel()

	c := &usernsChecker{
		getuid: func() int { return 1000 },
		readFile: func(_ string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
	}

	// If the sysctl doesn't exist, unprivileged userns is always enabled.
	err := c.check(context.Background())
	assert.NoError(t, err)
}

func TestUsernsCheck_Enabled(t *testing.T) {
	t.Parallel()

	c := &usernsChecker{
		getuid: func() int { return 1000 },
		readFile: func(_ string) ([]byte, error) {
			return []byte("1\n"), nil
		},
	}

	err := c.check(context.Background())
	assert.NoError(t, err)
}

func TestUsernsCheck_Disabled(t *testing.T) {
	t.Parallel()

	c := &usernsChecker{
		getuid: func() int { return 1000 },
		readFile: func(_ string) ([]byte, error) {
			return []byte("0\n"), nil
		},
	}

	err := c.check(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unprivileged user namespaces are disabled")
	assert.Contains(t, err.Error(), "kernel.unprivileged_userns_clone=1")
}

func TestUsernsCheck_ReadError(t *testing.T) {
	t.Parallel()

	c := &usernsChecker{
		getuid: func() int { return 1000 },
		readFile: func(_ string) ([]byte, error) {
			return nil, fmt.Errorf("permission denied")
		},
	}

	err := c.check(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot read")
}

func TestUserNamespaceCheck_ReturnsCheck(t *testing.T) {
	t.Parallel()

	check := UserNamespaceCheck()
	assert.Equal(t, "userns", check.Name)
	assert.True(t, check.Required)
	assert.NotNil(t, check.Run)
}
