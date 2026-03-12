// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package runner

import "os/exec"

// applyUserNamespace is a no-op on non-Linux platforms. User namespaces
// are a Linux-specific feature.
func applyUserNamespace(_ *exec.Cmd, _ *UserNamespaceConfig) {}
