// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package virtiofs_test

import (
	"context"
	"log"

	"github.com/stacklok/go-microvm/virtiofs"
)

func ExamplePrepareOwnership() {
	// Prepare a newly created subtree of an existing virtio-fs backing
	// directory for the fixed guest service account.
	if err := virtiofs.PrepareOwnership(context.Background(), "/srv/vm-share", "results", 65532, 65532); err != nil {
		log.Fatal(err)
	}
}
