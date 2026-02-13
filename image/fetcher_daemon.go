// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
)

// DaemonFetcher pulls images from the local Docker/Podman daemon via the
// container engine's Unix socket. Auth is handled by the daemon itself.
type DaemonFetcher struct{}

// Pull fetches an OCI image from the local container daemon.
func (DaemonFetcher) Pull(ctx context.Context, ref string) (v1.Image, error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parse reference: %w", err)
	}
	return daemon.Image(parsed, daemon.WithContext(ctx))
}
