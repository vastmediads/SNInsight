package logger

import (
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var globalLogger *zap.SugaredLogger

// Config 日志配置
type Config struct {
	Level     string
	File      string
	MaxSizeMB int
	MaxFiles  int
	ToStderr  bool // 非 TUI 模式同时输出到 stderr
}

// Init 初始化全局日志
func Init(cfg Config) error {
	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		level = zapcore.WarnLevel
	}

	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	var cores []zapcore.Core

	// 文件输出
	if cfg.File != "" {
		// 确保目录存在
		dir := filepath.Dir(cfg.File)
		if err := os.MkdirAll(dir, 0750); err != nil {
			return err
		}

		fileWriter := &lumberjack.Logger{
			Filename:   cfg.File,
			MaxSize:    cfg.MaxSizeMB,
			MaxBackups: cfg.MaxFiles,
			LocalTime:  true,
			Compress:   false,
		}
		fileCore := zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderConfig),
			zapcore.AddSync(fileWriter),
			level,
		)
		cores = append(cores, fileCore)
	}

	// stderr 输出 (非 TUI 模式)
	if cfg.ToStderr {
		consoleEncoder := zapcore.NewConsoleEncoder(encoderConfig)
		consoleCore := zapcore.NewCore(
			consoleEncoder,
			zapcore.AddSync(os.Stderr),
			level,
		)
		cores = append(cores, consoleCore)
	}

	// 如果没有任何输出，默认输出到 stderr
	if len(cores) == 0 {
		consoleCore := zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			zapcore.AddSync(os.Stderr),
			level,
		)
		cores = append(cores, consoleCore)
	}

	core := zapcore.NewTee(cores...)
	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
	globalLogger = logger.Sugar()

	return nil
}

// Debug 调试日志
func Debug(msg string, keysAndValues ...interface{}) {
	if globalLogger != nil {
		globalLogger.Debugw(msg, keysAndValues...)
	}
}

// Info 信息日志
func Info(msg string, keysAndValues ...interface{}) {
	if globalLogger != nil {
		globalLogger.Infow(msg, keysAndValues...)
	}
}

// Warn 警告日志
func Warn(msg string, keysAndValues ...interface{}) {
	if globalLogger != nil {
		globalLogger.Warnw(msg, keysAndValues...)
	}
}

// Error 错误日志
func Error(msg string, keysAndValues ...interface{}) {
	if globalLogger != nil {
		globalLogger.Errorw(msg, keysAndValues...)
	}
}

// Sync 刷新日志缓冲
func Sync() {
	if globalLogger != nil {
		_ = globalLogger.Sync()
	}
}
