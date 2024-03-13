/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: MPL-2.0
*/

package db

import (
	"encoding/hex"
	"errors"
	"fmt"

	sqlcipher "github.com/berty/gorm-sqlcipher"
	"github.com/edgelesssys/ego-mpc/internal/types"
	"gorm.io/gorm"
)

const KeySize = 32

var ErrNotFound = errors.New("entity not found")

type EncryptedDB struct {
	*gorm.DB
}

// New creates a new encrypted database.
func New(dbFilePath string, key []byte, typesToRegister ...any) (*EncryptedDB, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size: expected %v, got %v", KeySize, len(key))
	}
	db, err := gorm.Open(sqlcipher.Open(dbFilePath+"?_pragma_key="+hex.EncodeToString(key)), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true, // needed to update entries using .Save() without failing foreign key constraints
	})
	if err != nil {
		return nil, err
	}
	// to link tables
	err = db.Exec("PRAGMA foreign_keys = ON;").Error
	if err != nil {
		return nil, err
	}
	err = db.AutoMigrate(append(typesToRegister, types.EdgelessConfig{})...)
	if err != nil {
		return nil, err
	}
	return &EncryptedDB{
		DB: db,
	}, nil
}
