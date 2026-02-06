package models

import (
	"github.com/shopspring/decimal"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name     string `gorm:"size:50;not null"`
	Email    string `gorm:"uniqueIndex;size:255;not null"`
	Password string `gorm:"size:255"`
}

type Account struct {
	gorm.Model
	UserID   uint64          `gorm:"index;not null"`
	Currency string          `gorm:"size:3;index;not null"`
	Balance  decimal.Decimal `gorm:"not null"`
}

type Transaction struct {
	gorm.Model
	UserID uint64 `gorm:"index"`
	Type   string // transfer | exchange
	Status string // pending | completed | failed
	Currency string `gorm:"size:3;index;not null"`
}

type LedgerEntry struct {
	gorm.Model
	TxID      uint64 `gorm:"index"`
	AccountID uint64 `gorm:"index"`
	Currency  string `gorm:"size:3;index;not null"`
	Amount    decimal.Decimal
}
