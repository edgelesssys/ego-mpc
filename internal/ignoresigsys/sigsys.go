/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: MPL-2.0
*/

package ignoresigsys

import (
	"os/signal"
	"syscall"
)

func init() {
	// don't panic on EGo API calls outside the EGo runtime on macOS
	signal.Ignore(syscall.SIGSYS)
}
