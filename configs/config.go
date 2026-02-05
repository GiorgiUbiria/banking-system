package configs

import (
	"errors"

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
			logger.Log.Fatal("config file not found", zap.Error(err))
		}
		logger.Log.Fatal("failed to read config", zap.Error(err))
	}

	viper.Unmarshal(&AppConfig)
}
