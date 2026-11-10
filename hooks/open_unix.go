// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hooks

import "syscall"

const openNoFollowFlag = syscall.O_NOFOLLOW
