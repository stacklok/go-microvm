// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"context"

	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// ImageFetcher abstracts OCI image retrieval for testability.
type ImageFetcher interface {
	Pull(ctx context.Context, ref string) (v1.Image, error)
}

// CraneFetcher is the default ImageFetcher using crane.Pull.
type CraneFetcher struct{}

// Pull fetches an OCI image using crane.
func (CraneFetcher) Pull(ctx context.Context, ref string) (v1.Image, error) {
	return crane.Pull(ref, crane.WithContext(ctx))
}
