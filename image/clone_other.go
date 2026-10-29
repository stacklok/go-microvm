// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package image

import "errors"

func cloneFile(_, _ string) error { return errors.ErrUnsupported }

func cloneTree(_, _ string) error { return errCloneTreeUnsupported }
