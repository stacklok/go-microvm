// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package disk provides disk image download, caching, and decompression.
// It supports downloading compressed (zstd) disk images or tar archives
// from HTTP URLs with SHA-256 checksum verification, retry with exponential
// backoff, and progress reporting. Downloaded files are cached by URL to
// avoid redundant downloads.
package disk
