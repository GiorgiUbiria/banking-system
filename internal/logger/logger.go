package logger

import "go.uber.org/zap"

var Log *zap.Logger

func Init() {
	Log = zap.Must(zap.NewProduction())
}

func Sugar() *zap.SugaredLogger {
	return Log.Sugar()
}
