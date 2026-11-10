// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package image

import (
	"errors"
	"os"
)

func cloneFile(_, _ string) error { return errors.ErrUnsupported }

func cloneTree(_, _ string) error { return errCloneTreeUnsupported }

func fileOwner(_ os.FileInfo) (int, int, bool) { return 0, 0, false }
