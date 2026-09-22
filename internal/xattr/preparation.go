// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package xattr

import (
	"fmt"
	"strings"
)

const maxPreparationErrors = 16

// PreparationReport describes recoverable entries that could not be prepared.
// Error details are bounded so a large tree cannot produce an unbounded report.
type PreparationReport struct {
	Errors  []error
	Omitted int
}

// Complete reports whether every selected entry was prepared.
func (r PreparationReport) Complete() bool { return len(r.Errors) == 0 && r.Omitted == 0 }

func (r PreparationReport) Error() string {
	parts := make([]string, 0, len(r.Errors)+1)
	for _, err := range r.Errors {
		parts = append(parts, err.Error())
	}
	if r.Omitted > 0 {
		parts = append(parts, fmt.Sprintf("%d additional errors omitted", r.Omitted))
	}
	return strings.Join(parts, "; ")
}

func (r *PreparationReport) add(err error) {
	if len(r.Errors) < maxPreparationErrors {
		r.Errors = append(r.Errors, err)
	} else {
		r.Omitted++
	}
}
