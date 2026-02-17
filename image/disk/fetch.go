// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package disk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
)

// Option configures a Fetch call.
type Option interface {
	apply(*fetchConfig)
}

type optionFunc func(*fetchConfig)

func (f optionFunc) apply(c *fetchConfig) { f(c) }

// fetchConfig holds configuration assembled from Option values.
type fetchConfig struct {
	client   *http.Client
	checksum string
	progress func(downloaded, total int64)
}

// WithHTTPClient sets a custom HTTP client for the download.
func WithHTTPClient(c *http.Client) Option {
	return optionFunc(func(cfg *fetchConfig) { cfg.client = c })
}

// WithChecksum sets the expected SHA-256 hex checksum for verification.
func WithChecksum(sha256Hex string) Option {
	return optionFunc(func(cfg *fetchConfig) { cfg.checksum = sha256Hex })
}

// WithProgress sets a callback for download progress updates.
func WithProgress(fn func(downloaded, total int64)) Option {
	return optionFunc(func(cfg *fetchConfig) { cfg.progress = fn })
}

// Fetch downloads a file from url into cacheDir and returns the local path.
// If the file already exists (and passes checksum verification when a
// checksum is configured), it is returned immediately. Downloads are
// retried with exponential backoff on transient failures.
func Fetch(ctx context.Context, url, cacheDir string, opts ...Option) (string, error) {
	cfg := &fetchConfig{
		client: newHTTPClient(),
	}
	for _, o := range opts {
		o.apply(cfg)
	}

	// Derive the cache filename from the last path component of the URL.
	filename := filepath.Base(url)
	if filename == "" || filename == "." || filename == "/" {
		return "", fmt.Errorf("cannot derive filename from URL %q", url)
	}
	// Strip query string if present.
	if idx := strings.IndexByte(filename, '?'); idx >= 0 {
		filename = filename[:idx]
	}

	destPath := filepath.Join(cacheDir, filename)

	// Fast path: if the file already exists and checksum matches, return it.
	if _, err := os.Stat(destPath); err == nil {
		if cfg.checksum != "" {
			if err := verifyChecksum(destPath, cfg.checksum); err != nil {
				slog.Warn("cached file checksum mismatch, re-downloading",
					"path", destPath, "err", err)
				_ = os.Remove(destPath)
			} else {
				slog.Debug("using cached download", "path", destPath)
				return destPath, nil
			}
		} else {
			slog.Debug("using cached download", "path", destPath)
			return destPath, nil
		}
	}

	// Ensure cache directory exists.
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return "", fmt.Errorf("create cache directory %q: %w", cacheDir, err)
	}

	// Retry download with exponential backoff.
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = 2 * time.Second
	bo.MaxInterval = 30 * time.Second
	bo.MaxElapsedTime = 3 * time.Minute

	bCtx := backoff.WithContext(bo, ctx)

	operation := func() error {
		return downloadFile(ctx, cfg.client, url, destPath, cfg.progress)
	}

	if err := backoff.Retry(operation, bCtx); err != nil {
		return "", fmt.Errorf("download %q after retries: %w", url, err)
	}

	// Verify checksum if provided.
	if cfg.checksum != "" {
		if err := verifyChecksum(destPath, cfg.checksum); err != nil {
			_ = os.Remove(destPath)
			return "", err
		}
	}

	return destPath, nil
}

// newHTTPClient creates an http.Client with sensible transport timeouts
// for downloading large files.
func newHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConnsPerHost:   4,
			DisableKeepAlives:     false,
			ForceAttemptHTTP2:     true,
		},
	}
}

// downloadFile performs a single HTTP GET and writes the response body to
// destPath. It writes to a temporary file first and renames on success to
// avoid partial files.
func downloadFile(ctx context.Context, client *http.Client, url, destPath string, progress func(downloaded, total int64)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return backoff.Permanent(fmt.Errorf("create request: %w", err))
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP GET %q: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// 4xx errors are permanent (not retryable), 5xx are transient.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return backoff.Permanent(fmt.Errorf("HTTP %d for %q", resp.StatusCode, url))
		}
		return fmt.Errorf("HTTP %d for %q", resp.StatusCode, url)
	}

	// Write to a temp file in the same directory to ensure atomic rename.
	tmpFile, err := os.CreateTemp(filepath.Dir(destPath), ".download-*")
	if err != nil {
		return backoff.Permanent(fmt.Errorf("create temp file: %w", err))
	}
	tmpPath := tmpFile.Name()

	var body io.Reader = resp.Body
	if progress != nil {
		body = &progressReader{
			reader:   resp.Body,
			total:    resp.ContentLength,
			progress: progress,
		}
	}

	if _, err := io.Copy(tmpFile, body); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write response body: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return backoff.Permanent(fmt.Errorf("close temp file: %w", err))
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		_ = os.Remove(tmpPath)
		return backoff.Permanent(fmt.Errorf("rename temp file: %w", err))
	}

	return nil
}

// verifyChecksum computes the SHA-256 of a file and compares it to the
// expected hex-encoded checksum.
func verifyChecksum(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open file for checksum: %w", err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("compute SHA-256: %w", err)
	}

	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expected, actual)
	}

	return nil
}

// progressReader wraps an io.Reader and reports download progress via a
// callback. It tracks bytes read with an atomic counter for safety.
type progressReader struct {
	reader   io.Reader
	total    int64
	read     atomic.Int64
	progress func(downloaded, total int64)
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	if n > 0 {
		downloaded := pr.read.Add(int64(n))
		pr.progress(downloaded, pr.total)
	}
	return n, err
}
