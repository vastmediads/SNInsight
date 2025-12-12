package config

import (
	"time"
)

// Config 应用配置
type Config struct {
	Interfaces []string      `mapstructure:"interfaces"`
	Filter     FilterConfig  `mapstructure:"filter"`
	Display    DisplayConfig `mapstructure:"display"`
	Logging    LogConfig     `mapstructure:"logging"`
	Output     OutputConfig  `mapstructure:"output"`
}

// FilterConfig 过滤配置
type FilterConfig struct {
	BPF            string   `mapstructure:"bpf"`
	IncludeDomains []string `mapstructure:"include_domains"`
	ExcludeDomains []string `mapstructure:"exclude_domains"`
	SNIOnly        bool     `mapstructure:"sni_only"`
}

// DisplayConfig 显示配置
type DisplayConfig struct {
	Refresh time.Duration `mapstructure:"refresh"`
	MaxRows int           `mapstructure:"max_rows"`
}

// LogConfig 日志配置
type LogConfig struct {
	Level     string `mapstructure:"level"`
	File      string `mapstructure:"file"`
	MaxSizeMB int    `mapstructure:"max_size_mb"`
	MaxFiles  int    `mapstructure:"max_files"`
}

// OutputConfig 输出配置
type OutputConfig struct {
	Duration time.Duration `mapstructure:"duration"`
	File     string        `mapstructure:"file"`
	Format   string        `mapstructure:"format"`
	NoTUI    bool          `mapstructure:"no_tui"`
}

// Default 返回默认配置
func Default() *Config {
	return &Config{
		Interfaces: nil, // nil 表示所有非回环网卡
		Filter: FilterConfig{
			BPF:            "",
			IncludeDomains: nil,
			ExcludeDomains: nil,
			SNIOnly:        false,
		},
		Display: DisplayConfig{
			Refresh: time.Second,
			MaxRows: 50,
		},
		Logging: LogConfig{
			Level:     "warn",
			File:      "/var/log/sninsight/sninsight.log",
			MaxSizeMB: 10,
			MaxFiles:  3,
		},
		Output: OutputConfig{
			Duration: 0, // 0 表示持续运行
			File:     "",
			Format:   "json",
			NoTUI:    false,
		},
	}
}
