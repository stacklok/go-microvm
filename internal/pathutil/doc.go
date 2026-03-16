// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package pathutil provides path validation helpers shared across go-microvm
// packages. The primary use case is verifying that a guest-relative path
// resolves within a root directory, preventing path traversal attacks via
// ".." components or absolute paths.
package pathutil
