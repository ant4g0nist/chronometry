// Copyright 2023 WeFuzz Research and Development B.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import (
	"strconv"
	"sync"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	Logger     *zap.Logger
	loggerOnce sync.Once
)

type LoggerOpts struct {
	LogLevel      string `yaml:"log_level"`
	AccessLogFile string `yaml:"access_log"`
	ErrorLogFile  string `yaml:"error_log"`

	MaxSize    int `yaml:"max_size"`
	MaxBackups int `yaml:"max_backups"`
	MaxAge     int `yaml:"max_age"`
}

func InitLogger(cfg LoggerOpts) {
	loggerOnce.Do(func() {

		// Create a new encoder configuration
		encoderConfig := zapcore.EncoderConfig{
			TimeKey:        "time",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			MessageKey:     "message",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.CapitalLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		}

		// Create a new console encoder
		encoder := zapcore.NewJSONEncoder(encoderConfig)

		accessLog := zapcore.AddSync(&lumberjack.Logger{
			Filename:   cfg.AccessLogFile,
			MaxSize:    cfg.MaxSize, // megabytes
			MaxBackups: cfg.MaxBackups,
			MaxAge:     cfg.MaxAge, // days
		})

		errorLog := zapcore.AddSync(&lumberjack.Logger{
			Filename:   cfg.ErrorLogFile,
			MaxSize:    cfg.MaxSize, // megabytes
			MaxBackups: cfg.MaxBackups,
			MaxAge:     cfg.MaxAge, // days
		})

		logLevel := zap.NewAtomicLevelAt(zap.DebugLevel)

		if cfg.LogLevel == "info" {
			logLevel = zap.NewAtomicLevelAt(zap.InfoLevel)
		} else if cfg.LogLevel == "WARN" {
			logLevel = zap.NewAtomicLevelAt(zap.WarnLevel)
		} else if cfg.LogLevel == "ERROR" {
			logLevel = zap.NewAtomicLevelAt(zap.ErrorLevel)
		}

		// Create a new core that writes to both access log and error log
		core := zapcore.NewTee(
			zapcore.NewCore(encoder, accessLog, logLevel),
			zapcore.NewCore(encoder, errorLog, zap.NewAtomicLevelAt(zap.ErrorLevel)),
		)

		// Create a new logger with the specified core
		Logger = zap.New(core)
	})
}

// https://github.com/thomasvvugt/fiber-boilerplate/blob/master/app/middleware/access_logger.go#L90
func LoggerMiddleware() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		// Handle the request to calculate the number of bytes sent
		err := ctx.Next()

		// Chained error
		if err != nil {
			if chainErr := ctx.App().Config().ErrorHandler(ctx, err); chainErr != nil {
				_ = ctx.SendStatus(fiber.StatusInternalServerError)
			}
		}

		// Send structured information message to the logger
		Logger.Info(ctx.IP()+" - "+ctx.Method()+" "+ctx.OriginalURL()+" - "+strconv.Itoa(ctx.Response().StatusCode())+
			" - "+strconv.Itoa(len(ctx.Response().Body())),

			zap.String("ip", ctx.IP()),
			zap.String("hostname", ctx.Hostname()),
			zap.String("method", ctx.Method()),
			zap.String("path", ctx.OriginalURL()),
			zap.String("protocol", ctx.Protocol()),
			zap.Int("status", ctx.Response().StatusCode()),

			zap.String("x-forwarded-for", ctx.Get(fiber.HeaderXForwardedFor)),
			zap.String("user-agent", ctx.Get(fiber.HeaderUserAgent)),
			zap.String("referer", ctx.Get(fiber.HeaderReferer)),

			zap.Int("bytes_received", len(ctx.Request().Body())),
			zap.Int("bytes_sent", len(ctx.Response().Body())),
		)

		return err
	}
}
