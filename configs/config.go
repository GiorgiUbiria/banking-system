package configs

import (
	"errors"
	"os"

	"github.com/GiorgiUbiria/banking_system/internal/logger"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type Config struct {
	DB struct {
		DSN string `mapstructure:"dsn"`
	} `mapstructure:"db"`
	JWT struct {
		SECRET string `mapstructure:"secret"`
	} `mapstructure:"jwt"`
	ExchangeRate struct {
		UsdToEur float64 `mapstructure:"usd_to_eur"`
	} `mapstructure:"exchange-rate"`
}

var AppConfig Config

func LoadConfig() {
	viper.AddConfigPath("./configs")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	viper.AutomaticEnv()

	var fileLookupError viper.ConfigFileNotFoundError
	if err := viper.ReadInConfig(); err != nil {
		if errors.As(err, &fileLookupError) {
			logger.Log.Info("config file not found, using environment variables")
			AppConfig.ExchangeRate.UsdToEur = 0.92
		} else {
			logger.Log.Fatal("failed to read config", zap.Error(err))
		}
	} else {
		viper.Unmarshal(&AppConfig)
	}

	if v := os.Getenv("DATABASE_URL"); v != "" {
		AppConfig.DB.DSN = v
	}
	if v := os.Getenv("JWT_SECRET"); v != "" {
		AppConfig.JWT.SECRET = v
	}

	if AppConfig.DB.DSN == "" {
		logger.Log.Fatal("DATABASE_URL or config db.dsn is required")
	}
	if AppConfig.JWT.SECRET == "" {
		logger.Log.Fatal("JWT_SECRET or config jwt.secret is required")
	}
}
