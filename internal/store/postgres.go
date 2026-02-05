package store

import (
	"github.com/GiorgiUbiria/banking_system/configs"
	"github.com/GiorgiUbiria/banking_system/internal/logger"
	"github.com/GiorgiUbiria/banking_system/internal/models"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func NewDB() {
	dsn := configs.AppConfig.DB.DSN
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  dsn,
		PreferSimpleProtocol: false,
	}), &gorm.Config{})
	if err != nil {
		logger.Log.Fatal("failed to connect to database", zap.Error(err))
	}
	DB = db
	logger.Log.Info("connected to the database")
}

func DBMigrate() {
	DB.AutoMigrate(&models.Account{}, &models.User{}, &models.LedgerEntry{}, &models.Transaction{})
	logger.Log.Info("migrations loaded")
}
