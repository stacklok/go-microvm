// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ImageFetcher abstracts OCI image retrieval for testability.
type ImageFetcher interface {
	Pull(ctx context.Context, ref string) (v1.Image, error)
}

// RemoteFetcher pulls images from OCI registries using the go-containerregistry
// remote API. It uses authn.DefaultKeychain when Keychain is nil, which checks
// Docker/Podman credential stores automatically.
type RemoteFetcher struct {
	Keychain authn.Keychain // nil = authn.DefaultKeychain
}

// Pull fetches an OCI image from a remote registry.
func (f RemoteFetcher) Pull(ctx context.Context, ref string) (v1.Image, error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parse reference: %w", err)
	}
	kc := f.Keychain
	if kc == nil {
		kc = authn.DefaultKeychain
	}
	return remote.Image(parsed,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(kc),
	)
}
