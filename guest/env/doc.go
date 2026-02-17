// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package env parses shell-escaped environment files (e.g. /etc/sandbox-env)
// written by host-side rootfs hooks into KEY=value pairs suitable for
// os/exec.Cmd.Env. The format is one "export KEY='value'" per line, with
// single-quote escaping for special characters.
package env
