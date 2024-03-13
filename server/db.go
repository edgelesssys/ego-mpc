/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: MPL-2.0
*/

package server

import (
	"crypto"
	"crypto/x509"
	"errors"

	"github.com/edgelesssys/ego-mpc/db"
	"github.com/edgelesssys/ego-mpc/internal/types"
	"gorm.io/gorm"
)

type serverDB struct {
	*db.EncryptedDB
}

func (d *serverDB) setConfig(cert []byte, key crypto.PrivateKey, rawOwnerCert []byte) error {
	keyRaw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := d.Create(types.EdgelessConfig{Certificate: cert, Key: keyRaw, Owner: rawOwnerCert}).Error; err != nil {
		return err
	}
	return nil
}

func (d *serverDB) getCertificate() ([]byte, crypto.PrivateKey, error) {
	var cfg types.EdgelessConfig
	if err := d.First(&cfg).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil, db.ErrNotFound
	} else if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(cfg.Key)
	if err != nil {
		return nil, nil, err
	}
	return cfg.Certificate, key, nil
}

func (d *serverDB) getOwner() ([]byte, error) {
	var cfg types.EdgelessConfig
	if err := d.First(&cfg).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, db.ErrNotFound
	} else if err != nil {
		return nil, err
	}
	return cfg.Owner, nil
}
