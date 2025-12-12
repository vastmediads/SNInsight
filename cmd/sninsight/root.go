package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/nickproject/sninsight/internal/config"
)

var (
	cfgFile string
	cfg     *config.Config
)

var rootCmd = &cobra.Command{
	Use:   "sninsight",
	Short: "基于 eBPF 的网络流量监控工具",
	Long: `Sninsight 是一个基于 eBPF 的网络流量监控工具。
支持实时监控网络流量，解析 TLS SNI 识别域名，
通过 TUI 界面实时展示流量统计。`,
	RunE: runMonitor,
}

func init() {
	cobra.OnInitialize(initConfig)

	// 基础选项
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "配置文件路径")
	rootCmd.Flags().StringSliceP("interface", "i", nil, "指定网卡 (可多次指定)")
	rootCmd.Flags().DurationP("refresh", "r", time.Second, "刷新间隔")

	// 过滤选项
	rootCmd.Flags().StringP("filter", "f", "", "BPF 过滤表达式")
	rootCmd.Flags().StringSlice("include-domains", nil, "域名白名单 (逗号分隔)")
	rootCmd.Flags().StringSlice("exclude-domains", nil, "域名黑名单 (逗号分隔)")

	// 输出选项
	rootCmd.Flags().DurationP("duration", "d", 0, "运行时长后退出")
	rootCmd.Flags().StringP("output", "o", "", "导出文件路径")
	rootCmd.Flags().String("format", "json", "导出格式 (json|csv)")
	rootCmd.Flags().Bool("no-tui", false, "禁用 TUI")

	// 日志选项
	rootCmd.Flags().String("log-file", "", "日志文件路径")
	rootCmd.Flags().String("log-level", "warn", "日志级别 (debug|info|warn|error)")

	// 绑定到 viper
	viper.BindPFlag("interfaces", rootCmd.Flags().Lookup("interface"))
	viper.BindPFlag("display.refresh", rootCmd.Flags().Lookup("refresh"))
	viper.BindPFlag("filter.bpf", rootCmd.Flags().Lookup("filter"))
	viper.BindPFlag("filter.include_domains", rootCmd.Flags().Lookup("include-domains"))
	viper.BindPFlag("filter.exclude_domains", rootCmd.Flags().Lookup("exclude-domains"))
	viper.BindPFlag("output.duration", rootCmd.Flags().Lookup("duration"))
	viper.BindPFlag("output.file", rootCmd.Flags().Lookup("output"))
	viper.BindPFlag("output.format", rootCmd.Flags().Lookup("format"))
	viper.BindPFlag("output.no_tui", rootCmd.Flags().Lookup("no-tui"))
	viper.BindPFlag("logging.file", rootCmd.Flags().Lookup("log-file"))
	viper.BindPFlag("logging.level", rootCmd.Flags().Lookup("log-level"))
}

func initConfig() {
	cfg = config.Default()

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		// 搜索配置文件
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(home + "/.config/sninsight")
		}
		viper.AddConfigPath("/etc/sninsight")
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	// 环境变量
	viper.SetEnvPrefix("SNINSIGHT")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Fprintf(os.Stderr, "读取配置文件错误: %v\n", err)
			os.Exit(1)
		}
	}

	// 解析到结构体
	if err := viper.Unmarshal(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "解析配置错误: %v\n", err)
		os.Exit(1)
	}
}

func runMonitor(cmd *cobra.Command, args []string) error {
	// 权限检查
	if err := checkPermissions(); err != nil {
		return err
	}

	// TODO: 启动监控 (将在 Task 12 实现)
	fmt.Printf("Sninsight v0.1.0 (%s/%s)\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("配置: %+v\n", cfg)

	return fmt.Errorf("监控功能尚未完全实现")
}

func checkPermissions() error {
	if runtime.GOOS == "linux" {
		// Linux: 检查 root 或 CAP_NET_ADMIN
		if os.Geteuid() != 0 {
			return fmt.Errorf("需要 root 权限或 CAP_NET_ADMIN 能力")
		}
	} else if runtime.GOOS == "darwin" {
		// macOS: 检查 root 或 BPF 访问权限
		if os.Geteuid() != 0 {
			// 检查 /dev/bpf* 是否可访问
			if _, err := os.Stat("/dev/bpf0"); os.IsPermission(err) {
				return fmt.Errorf("需要 sudo 权限或加入 access_bpf 组")
			}
		}
	}
	return nil
}

func Execute() error {
	return rootCmd.Execute()
}
