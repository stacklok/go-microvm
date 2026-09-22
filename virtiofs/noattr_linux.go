// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package virtiofs

import (
	"errors"

	"golang.org/x/sys/unix"
)

func isNoAttribute(err error) bool { return errors.Is(err, unix.ENODATA) }
