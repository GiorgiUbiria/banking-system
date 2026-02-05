package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/GiorgiUbiria/banking_system/configs"
	"github.com/GiorgiUbiria/banking_system/internal/logger"
	"github.com/GiorgiUbiria/banking_system/internal/routes"
	"github.com/GiorgiUbiria/banking_system/internal/seed"
	"github.com/GiorgiUbiria/banking_system/internal/store"
	"go.uber.org/zap"
)

func main() {
	logger.Init()
	defer logger.Log.Sync()

	configs.LoadConfig()
	store.NewDB()
	store.DBMigrate()
	seed.Run()

	router := routes.NewRoutes()

	srv := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Log.Info("HTTP server listening", zap.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Log.Fatal("server error", zap.Error(err))
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	logger.Log.Info("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Log.Error("graceful shutdown failed", zap.Error(err))
	}

	sqlDB, err := store.DB.DB()
	if err != nil {
		logger.Log.Error("db close skipped, reason:", zap.Error(err))
	} else {
		sqlDB.Close()
		logger.Log.Info("db closed")
	}

	logger.Log.Info("server stopped")
}
