// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefault_ReturnsNonNil(t *testing.T) {
	t.Parallel()

	c := Default()
	require.NotNil(t, c)
}

func TestNewEmpty_ReturnsCheckerWithNoChecks(t *testing.T) {
	t.Parallel()

	c := NewEmpty()
	require.NotNil(t, c)

	// Running all checks on an empty checker should succeed.
	err := c.RunAll(context.Background())
	assert.NoError(t, err)
}

func TestChecker_Register(t *testing.T) {
	t.Parallel()

	c := NewEmpty()

	called := false
	c.Register(Check{
		Name:        "test-check",
		Description: "A test check",
		Run: func(_ context.Context) error {
			called = true
			return nil
		},
		Required: true,
	})

	err := c.RunAll(context.Background())
	require.NoError(t, err)
	assert.True(t, called, "registered check should have been called")
}

func TestChecker_RunAll_AllPass(t *testing.T) {
	t.Parallel()

	c := NewEmpty()

	c.Register(Check{
		Name:     "pass-1",
		Run:      func(_ context.Context) error { return nil },
		Required: true,
	})
	c.Register(Check{
		Name:     "pass-2",
		Run:      func(_ context.Context) error { return nil },
		Required: true,
	})

	err := c.RunAll(context.Background())
	assert.NoError(t, err)
}

func TestChecker_RunAll_RequiredCheckFails(t *testing.T) {
	t.Parallel()

	c := NewEmpty()

	c.Register(Check{
		Name:     "required-fail",
		Run:      func(_ context.Context) error { return errors.New("hardware not found") },
		Required: true,
	})

	err := c.RunAll(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "preflight checks failed")
	assert.Contains(t, err.Error(), "required-fail")
	assert.Contains(t, err.Error(), "hardware not found")
}

func TestChecker_RunAll_NonRequiredCheckFailsButSucceeds(t *testing.T) {
	t.Parallel()

	c := NewEmpty()

	c.Register(Check{
		Name:     "optional-fail",
		Run:      func(_ context.Context) error { return errors.New("optional issue") },
		Required: false,
	})
	c.Register(Check{
		Name:     "required-pass",
		Run:      func(_ context.Context) error { return nil },
		Required: true,
	})

	err := c.RunAll(context.Background())
	assert.NoError(t, err, "non-required failure should not cause RunAll to fail")
}

func TestChecker_RunAll_MultipleRequiredFailures(t *testing.T) {
	t.Parallel()

	c := NewEmpty()

	c.Register(Check{
		Name:     "fail-1",
		Run:      func(_ context.Context) error { return errors.New("error one") },
		Required: true,
	})
	c.Register(Check{
		Name:     "fail-2",
		Run:      func(_ context.Context) error { return errors.New("error two") },
		Required: true,
	})

	err := c.RunAll(context.Background())
	require.Error(t, err)

	errStr := err.Error()
	assert.Contains(t, errStr, "fail-1")
	assert.Contains(t, errStr, "fail-2")
	assert.Contains(t, errStr, "error one")
	assert.Contains(t, errStr, "error two")
}

func TestChecker_RunAll_ExecutionOrder(t *testing.T) {
	t.Parallel()

	c := NewEmpty()

	var order []string

	c.Register(Check{
		Name: "first",
		Run: func(_ context.Context) error {
			order = append(order, "first")
			return nil
		},
		Required: true,
	})
	c.Register(Check{
		Name: "second",
		Run: func(_ context.Context) error {
			order = append(order, "second")
			return nil
		},
		Required: true,
	})
	c.Register(Check{
		Name: "third",
		Run: func(_ context.Context) error {
			order = append(order, "third")
			return nil
		},
		Required: true,
	})

	err := c.RunAll(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"first", "second", "third"}, order)
}

func TestChecker_RunAll_MixedRequiredAndOptional(t *testing.T) {
	t.Parallel()

	c := NewEmpty()

	c.Register(Check{
		Name:     "optional-fail",
		Run:      func(_ context.Context) error { return errors.New("warn only") },
		Required: false,
	})
	c.Register(Check{
		Name:     "required-fail",
		Run:      func(_ context.Context) error { return errors.New("fatal") },
		Required: true,
	})

	err := c.RunAll(context.Background())
	require.Error(t, err)

	// The error should reference the required failure but not the optional one.
	assert.Contains(t, err.Error(), "required-fail")
	assert.Contains(t, err.Error(), "fatal")
	// The optional failure message should NOT appear in the returned error.
	assert.False(t, strings.Contains(err.Error(), "warn only"),
		"optional check failure should not appear in the error")
}
