// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// FallbackFetcher tries multiple ImageFetcher implementations in order,
// returning the first successful result. If all fetchers fail, errors are
// aggregated with errors.Join.
type FallbackFetcher struct {
	fetchers []ImageFetcher
}

// NewFallbackFetcher creates a FallbackFetcher that tries the given fetchers
// in order.
func NewFallbackFetcher(fetchers ...ImageFetcher) *FallbackFetcher {
	return &FallbackFetcher{fetchers: fetchers}
}

// NewLocalThenRemoteFetcher returns a FallbackFetcher that tries the local
// Docker/Podman daemon first, then falls back to pulling from a remote
// registry. This is useful when locally-built images should be resolved
// without pushing them to a registry.
func NewLocalThenRemoteFetcher() *FallbackFetcher {
	return NewFallbackFetcher(DaemonFetcher{}, RemoteFetcher{})
}

// Pull tries each fetcher in order, returning the first success.
func (f *FallbackFetcher) Pull(ctx context.Context, ref string) (v1.Image, error) {
	if len(f.fetchers) == 0 {
		return nil, fmt.Errorf("no fetchers configured")
	}

	var errs []error
	for i, fetcher := range f.fetchers {
		img, err := fetcher.Pull(ctx, ref)
		if err == nil {
			return img, nil
		}
		errs = append(errs, err)
		if i < len(f.fetchers)-1 {
			slog.Debug("fetcher failed, trying next",
				"fetcher_index", i,
				"error", err,
				"ref", ref,
			)
		}
	}

	return nil, fmt.Errorf("all fetchers failed for %q: %w", ref, errors.Join(errs...))
}
