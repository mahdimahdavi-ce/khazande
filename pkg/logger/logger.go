package logger

import "go.uber.org/zap"

func InitialLogger(level string) *zap.Logger {
	var logger *zap.Logger

	if level == "Production" {
		logger, _ = zap.NewProduction()
	} else {
		logger, _ = zap.NewDevelopment()
	}
	defer logger.Sync()

	return logger
}
