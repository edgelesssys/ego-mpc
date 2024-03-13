package db

/*
The db package defines the business logic related database schemas. It builds on top of GORM, a popular ORM library for Go.
*/

import (
	"github.com/edgelesssys/ego-mpc/db"
	"github.com/edgelesssys/ego-mpc/seal"
)

type DB struct {
	*db.EncryptedDB
}

func New(dbFilePath string) (*DB, error) {
	key, err := seal.GetOrCreateSealedKey(dbFilePath + ".sealed_key")
	if err != nil {
		return nil, err
	}
	// register all database models here
	dbBase, err := db.New(dbFilePath, key,
		&Account{})
	if err != nil {
		return nil, err
	}
	return &DB{EncryptedDB: dbBase}, nil
}

// CreateAccount creates a new account in the database. clientID is the ID of the client that the account belongs to.
func (db *DB) CreateAccount(account Account, clientID string) error {
	account.ClientID = clientID
	return db.Create(&account).Error
}

// GetAccounts returns all accounts of the given client.
func (db *DB) GetAccounts(clientID string) ([]Account, error) {
	var accounts []Account
	if err := db.Select("name, money").Where("client_id = ?", clientID).Find(&accounts).Error; err != nil {
		return nil, err
	}
	return accounts, nil
}

// GetGlobalMoney returns the sum of all money in the database.
func (db *DB) GetGlobalMoney() (int, error) {
	var totalMoney int
	if err := db.Model(&Account{}).Select("sum(money)").Row().Scan(&totalMoney); err != nil {
		return 0, err
	}
	return totalMoney, nil
}
