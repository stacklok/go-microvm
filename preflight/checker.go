// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package preflight provides an extensible system for running pre-boot
// verification checks before creating a microVM.
//
// Built-in checks verify hypervisor availability (KVM on Linux, HVF on macOS)
// and port availability. Callers may register additional checks via
// [Checker.Register].
package preflight

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Check represents a single preflight verification.
type Check struct {
	// Name is a short identifier for the check (e.g. "kvm", "ports").
	Name string

	// Description is a human-readable description of what the check verifies.
	Description string

	// Run executes the check. It should return nil on success or an error
	// with a descriptive message and remediation hints.
	Run func(ctx context.Context) error

	// Required indicates whether a failure should be treated as a fatal
	// error (true) or a warning (false).
	Required bool
}

// Checker runs preflight checks before VM creation.
type Checker interface {
	// RunAll executes all registered checks in order. It returns an error
	// if any required check fails. Non-required failures are logged as
	// warnings.
	RunAll(ctx context.Context) error

	// Register adds a check to the checker. Checks run in registration order.
	Register(check Check)
}

// checker is the default implementation of Checker.
type checker struct {
	checks []Check
}

// Default returns a Checker pre-populated with platform-specific built-in
// checks (KVM on Linux, HVF on macOS).
func Default() Checker {
	c := &checker{}
	registerPlatformChecks(c)
	return c
}

// NewEmpty returns a Checker with no pre-registered checks.
func NewEmpty() Checker {
	return &checker{}
}

// Register adds a check to the checker.
func (c *checker) Register(check Check) {
	c.checks = append(c.checks, check)
}

// RunAll executes all registered checks in order. Required check failures
// are collected and returned as a combined error. Non-required check failures
// are logged as warnings but do not cause RunAll to return an error.
func (c *checker) RunAll(ctx context.Context) error {
	tracer := otel.Tracer("github.com/stacklok/go-microvm")
	ctx, span := tracer.Start(ctx, "microvm.preflight.RunAll",
		trace.WithAttributes(attribute.Int("preflight.check_count", len(c.checks))))
	defer span.End()

	var errs []error

	for _, check := range c.checks {
		_, checkSpan := tracer.Start(ctx, "microvm.preflight.Check",
			trace.WithAttributes(
				attribute.String("preflight.check.name", check.Name),
				attribute.Bool("preflight.check.required", check.Required),
			))

		slog.Debug("running preflight check",
			"name", check.Name,
			"description", check.Description,
			"required", check.Required,
		)

		if err := check.Run(ctx); err != nil {
			checkSpan.RecordError(err)
			if check.Required {
				checkSpan.SetStatus(codes.Error, err.Error())
				slog.Error("preflight check failed",
					"name", check.Name,
					"error", err,
				)
				errs = append(errs, fmt.Errorf("check %q: %w", check.Name, err))
			} else {
				slog.Warn("preflight check failed (non-required)",
					"name", check.Name,
					"error", err,
				)
			}
		} else {
			slog.Debug("preflight check passed", "name", check.Name)
		}
		checkSpan.End()
	}

	if len(errs) > 0 {
		combinedErr := fmt.Errorf("preflight checks failed: %w", errors.Join(errs...))
		span.RecordError(combinedErr)
		span.SetStatus(codes.Error, combinedErr.Error())
		return combinedErr
	}

	return nil
}
