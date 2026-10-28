// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package pathutil

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileMode(t *testing.T) {
	t.Parallel()

	special := os.FileMode(0)
	if os.Geteuid() != 0 {
		special = os.ModeSetuid | os.ModeSetgid
	}
	assert.Equal(t, os.FileMode(0o644), FileMode(0o644))
	assert.Equal(t, os.FileMode(0o755), FileMode(os.ModeSticky|0o755))
	assert.Equal(t, special|0o755, FileMode(os.ModeSetuid|os.ModeSetgid|0o755))
}
