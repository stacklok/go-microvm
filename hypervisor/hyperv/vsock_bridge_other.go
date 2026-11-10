// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hyperv

import "net"

func defaultVsockListener(_ uint32) (net.Listener, error) {
	return nil, nil
}
