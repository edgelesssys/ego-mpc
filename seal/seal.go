/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: MPL-2.0
*/

/*
Package seal provides functions to seal and unseal data.

Sealing is the process of encrypting data with a key derived from the enclave and the CPU it is running
on. Sealed data can only be decrypted by the same enclave and CPU. Use it to persist data to disk.
*/
package seal

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"github.com/edgelesssys/ego-mpc/db"
	_ "github.com/edgelesssys/ego-mpc/internal/ignoresigsys" // don't panic on EGo API calls outside the EGo runtime on macOS
	"github.com/edgelesssys/ego/ecrypto"
)

func Seal(filename string, plaintext []byte) error {
	ciphertext, err := ecrypto.SealWithProductKey(plaintext, nil)
	if err != nil {
		return fmt.Errorf("sealing: %w", err)
	}
	if err := os.WriteFile(filename, ciphertext, 0o600); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}
	return nil
}

func Unseal(filename string) ([]byte, error) {
	ciphertext, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	plaintext, err := ecrypto.Unseal(ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("unsealing: %w", err)
	}
	return plaintext, nil
}

// GetOrCreateSealedKey reads a sealed key from a file.
// If the file doesn't exist, it is created and a new key is generated.
func GetOrCreateSealedKey(filename string) ([]byte, error) {
	key, err := Unseal(filename)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, db.KeySize)
		_, err := rand.Read(key)
		if err != nil {
			return nil, fmt.Errorf("generating key: %w", err)
		}
		if err := Seal(filename, key); err != nil {
			return nil, fmt.Errorf("sealing key: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("unsealing key: %w", err)
	}
	return key, nil
}
