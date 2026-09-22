// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package microvm_test

import (
	microvm "github.com/stacklok/go-microvm"
)

func ExampleVirtioFSMount_ownershipPreparationPolicy() {
	_ = microvm.WithVirtioFS(
		// The default reports incomplete ownership preparation and continues.
		microvm.VirtioFSMount{
			Tag: "workspace", HostPath: "/srv/workspace", OverrideUID: 65532,
		},
		// Mecatl requires complete ownership metadata before startup.
		microvm.VirtioFSMount{
			Tag: "mecatl", HostPath: "/srv/mecatl", OverrideUID: 65532,
			StrictOwnershipPreparation: true,
		},
	)
}
