//go:build !ego_mpc_mock

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: MPL-2.0
*/

package client

import (
	"bytes"
	"errors"
	"fmt"
	"log"

	"github.com/edgelesssys/ego/eclient"
)

func verifyReport(reportRaw []byte, uniqueID []byte, certHash []byte) error {
	log.Print("Verifying remote report")
	report, err := eclient.VerifyRemoteReport(reportRaw)
	if err != nil {
		return err
	}

	if !bytes.Equal(report.UniqueID, uniqueID) {
		return fmt.Errorf("invalid UniqueID: expected %x, got %x", uniqueID, report.UniqueID)
	}

	if !bytes.Equal(report.Data[:len(certHash)], certHash) {
		return errors.New("report data does not match the certificate's hash")
	}
	log.Print("Remote report successfully verified")
	return nil
}
