// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package xattr

import (
	"context"
	"fmt"
	"math"

	"github.com/stacklok/go-microvm/virtiofs"
)

// SetOverrideStatTree strictly prepares the entire root for virtio-fs ownership
// mapping. New code should call [virtiofs.PrepareOwnership] directly.
func SetOverrideStatTree(root string, uid, gid int) error {
	if uid < 0 || gid < 0 || uint64(uid) > math.MaxUint32 || uint64(gid) > math.MaxUint32 {
		return fmt.Errorf("override_stat uid/gid out of uint32 range: %d:%d", uid, gid)
	}
	return virtiofs.PrepareOwnership(context.Background(), root, ".", uint32(uid), uint32(gid))
}
