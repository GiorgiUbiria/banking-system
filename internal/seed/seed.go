package seed

import (
	"golang.org/x/crypto/bcrypt"

	"github.com/GiorgiUbiria/banking_system/internal/logger"
	"github.com/GiorgiUbiria/banking_system/internal/models"
	"github.com/GiorgiUbiria/banking_system/internal/store"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

const (
	seedPassword   = "password123"
	usdInitial     = "1000.00"
	eurInitial     = "500.00"
	systemEmail    = "system@bank.local"
)

var testUsers = []struct {
	Name  string
	Email string
}{
	{"Test User 1", "user1@test.com"},
	{"Test User 2", "user2@test.com"},
	{"Test User 3", "user3@test.com"},
}

func Run() {
	db := store.DB
	var count int64
	if err := db.Model(&models.User{}).Where("email IN ?", []string{"user1@test.com", "user2@test.com", "user3@test.com"}).Count(&count).Error; err != nil {
		logger.Log.Fatal("seed check failed", zap.Error(err))
	}
	if count >= 3 {
		logger.Log.Info("seed already applied, skipping")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(seedPassword), bcrypt.DefaultCost)
	if err != nil {
		logger.Log.Fatal("failed to hash seed password", zap.Error(err))
	}
	hashed := string(hash)

	err = db.Transaction(func(tx *gorm.DB) error {
		// System user for double-entry (negative side of opening balances)
		sys := models.User{Name: "System", Email: systemEmail, Password: hashed}
		if err := tx.Create(&sys).Error; err != nil {
			return err
		}
		usdZero := decimal.RequireFromString("0")
		sysUsd := models.Account{UserID: uint64(sys.ID), Currency: "USD", Balance: usdZero}
		sysEur := models.Account{UserID: uint64(sys.ID), Currency: "EUR", Balance: usdZero}
		if err := tx.Create(&sysUsd).Error; err != nil {
			return err
		}
		if err := tx.Create(&sysEur).Error; err != nil {
			return err
		}

		usd1000 := decimal.RequireFromString(usdInitial)
		eur500 := decimal.RequireFromString(eurInitial)
		usdMinus1000 := decimal.RequireFromString("-1000.00")
		eurMinus500 := decimal.RequireFromString("-500.00")

		for _, u := range testUsers {
			user := models.User{Name: u.Name, Email: u.Email, Password: hashed}
			if err := tx.Create(&user).Error; err != nil {
				return err
			}
			userUsd := models.Account{UserID: uint64(user.ID), Currency: "USD", Balance: usd1000}
			userEur := models.Account{UserID: uint64(user.ID), Currency: "EUR", Balance: eur500}
			if err := tx.Create(&userUsd).Error; err != nil {
				return err
			}
			if err := tx.Create(&userEur).Error; err != nil {
				return err
			}

			tr := models.Transaction{UserID: uint64(user.ID), Type: "seed", Status: "completed"}
			if err := tx.Create(&tr).Error; err != nil {
				return err
			}
			// Double-entry: system side negative, user side positive; sum = 0
			entries := []models.LedgerEntry{
				{TxID: uint64(tr.ID), AccountID: uint64(sysUsd.ID), Amount: usdMinus1000},
				{TxID: uint64(tr.ID), AccountID: uint64(userUsd.ID), Amount: usd1000},
				{TxID: uint64(tr.ID), AccountID: uint64(sysEur.ID), Amount: eurMinus500},
				{TxID: uint64(tr.ID), AccountID: uint64(userEur.ID), Amount: eur500},
			}
			for _, e := range entries {
				if err := tx.Create(&e).Error; err != nil {
					return err
				}
			}
		}

		sysUsdBal := decimal.RequireFromString("-3000.00")
		sysEurBal := decimal.RequireFromString("-1500.00")
		if err := tx.Model(&models.Account{}).Where("id = ?", sysUsd.ID).Update("balance", sysUsdBal).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.Account{}).Where("id = ?", sysEur.ID).Update("balance", sysEurBal).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		logger.Log.Fatal("seed failed", zap.Error(err))
	}
	logger.Log.Info("seeded 3 test users", zap.String("password", seedPassword))
}
