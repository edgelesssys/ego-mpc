//go:build ego_mpc_mock

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: MPL-2.0
*/

package client

import "log"

func verifyReport(reportRaw []byte, uniqueID []byte, certHash []byte) error {
	log.Print("WARNING: skipping remote attestation")
	return nil
}
