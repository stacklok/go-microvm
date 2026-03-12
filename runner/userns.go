// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package runner

// UserNamespaceConfig configures a Linux user namespace for the runner
// subprocess. When set, the runner is spawned inside a CLONE_NEWUSER
// namespace so that it gains CAP_SETUID/CAP_SETGID within the namespace.
// This allows libkrun's virtiofs passthrough to call set_creds() without
// requiring host-level capabilities.
//
// The UID and GID fields specify the single mapping from container
// namespace IDs to the host process's real UID/GID. For example, if the
// guest expects UID 1000 and the host process runs as UID 1000, set
// UID=1000 and GID=1000 to create the mapping 1000→1000.
type UserNamespaceConfig struct {
	// UID is the user ID inside the namespace that maps to the host UID.
	UID uint32
	// GID is the group ID inside the namespace that maps to the host GID.
	GID uint32
}
