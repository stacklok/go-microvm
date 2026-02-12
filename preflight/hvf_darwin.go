// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package preflight

// registerPlatformChecks adds macOS-specific preflight checks.
// Hypervisor.framework availability is difficult to check programmatically,
// so this is a no-op. The framework is available on all supported macOS
// versions with Apple Silicon.
func registerPlatformChecks(_ *checker) {
	// Intentionally empty. HVF is assumed to be available on macOS.
}
