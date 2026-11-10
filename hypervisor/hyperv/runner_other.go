// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hyperv

import (
	"context"
	"errors"
)

// ErrUnsupportedPlatform reports that Hyper-V is unavailable on this host.
var ErrUnsupportedPlatform = errors.New("hyperv backend is only supported on windows")

type defaultRunner struct{}

func (defaultRunner) CreateAndStart(_ context.Context, _ string, _ *ComputeSystem) (Handle, error) {
	return nil, ErrUnsupportedPlatform
}
