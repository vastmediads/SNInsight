package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/nickproject/sninsight/internal/aggregator"
	"github.com/nickproject/sninsight/internal/capture"
	"github.com/nickproject/sninsight/internal/config"
	"github.com/nickproject/sninsight/internal/diagnose"
	"github.com/nickproject/sninsight/internal/export"
	"github.com/nickproject/sninsight/internal/filter"
	"github.com/nickproject/sninsight/internal/logger"
	"github.com/nickproject/sninsight/internal/tui"
)

var (
	cfgFile        string
	cfg            *config.Config
	diagnoseEBPF   bool
	diagnoseSNI    bool
	testDomain     string
)

var rootCmd = &cobra.Command{
	Use:   "sninsight",
	Short: "基于 eBPF 的网络流量监控工具",
	Long: `Sninsight 是一个基于 eBPF 的网络流量监控工具。
支持实时监控网络流量，解析 TLS SNI 识别域名，
通过 TUI 界面实时展示流量统计。

诊断模式:
  --diagnose-ebpf    检查 eBPF 运行环境（权限、内核配置等）
  --diagnose-sni     检查 SNI 捕获功能（TLS 事件捕获、SNI 解析等）`,
	RunE: runMain,
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

	// 诊断选项
	rootCmd.Flags().BoolVar(&diagnoseEBPF, "diagnose-ebpf", false, "运行 eBPF 环境诊断")
	rootCmd.Flags().BoolVar(&diagnoseSNI, "diagnose-sni", false, "运行 SNI 捕获诊断")
	rootCmd.Flags().StringVar(&testDomain, "test-domain", "", "SNI 诊断使用的测试域名 (默认: cloudflare.com)")

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
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(home + "/.config/sninsight")
		}
		viper.AddConfigPath("/etc/sninsight")
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	viper.SetEnvPrefix("SNINSIGHT")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Fprintf(os.Stderr, "读取配置文件错误: %v\n", err)
			os.Exit(1)
		}
	}

	if err := viper.Unmarshal(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "解析配置错误: %v\n", err)
		os.Exit(1)
	}
}

// runMain 主入口，根据参数决定运行模式
func runMain(cmd *cobra.Command, args []string) error {
	// 诊断模式
	if diagnoseEBPF {
		return runDiagnoseEBPF()
	}
	if diagnoseSNI {
		return runDiagnoseSNI()
	}

	// 正常监控模式
	return runMonitor(cmd, args)
}

// runDiagnoseEBPF 运行 eBPF 环境诊断
func runDiagnoseEBPF() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("eBPF 诊断仅支持 Linux 平台")
	}

	report := diagnose.RunEBPFDiagnose()
	return report.OutputJSON()
}

// runDiagnoseSNI 运行 SNI 捕获诊断
func runDiagnoseSNI() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("SNI 诊断仅支持 Linux 平台")
	}

	report := diagnose.RunSNIDiagnose(testDomain)
	return report.OutputJSON()
}

func runMonitor(cmd *cobra.Command, args []string) error {
	// 初始化日志
	logCfg := logger.Config{
		Level:     cfg.Logging.Level,
		File:      cfg.Logging.File,
		MaxSizeMB: cfg.Logging.MaxSizeMB,
		MaxFiles:  cfg.Logging.MaxFiles,
		ToStderr:  cfg.Output.NoTUI,
	}
	if err := logger.Init(logCfg); err != nil {
		return fmt.Errorf("初始化日志失败: %w", err)
	}
	defer logger.Sync()

	// 权限检查
	if err := checkPermissions(); err != nil {
		return err
	}

	// 创建 context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 处理信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Info("收到退出信号")
		cancel()
	}()

	// 如果设置了 duration，添加超时
	if cfg.Output.Duration > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, cfg.Output.Duration)
		defer timeoutCancel()
	}

	// 创建抓包器
	captureCfg := capture.CaptureConfig{
		Interfaces: cfg.Interfaces,
		BPFFilter:  cfg.Filter.BPF,
	}
	capturer, err := capture.New(captureCfg)
	if err != nil {
		return fmt.Errorf("创建抓包器失败: %w", err)
	}

	// 创建过滤器
	domainFilter := filter.New(cfg.Filter.IncludeDomains, cfg.Filter.ExcludeDomains)

	// 创建聚合器
	caps := capturer.Capabilities()
	agg := aggregator.NewAggregator(domainFilter, caps.SupportsDirection, cfg.Display.Refresh)

	// 创建输出通道
	entriesChan := make(chan []aggregator.TrafficEntry, 10)

	// 启动抓包
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := capturer.Start(ctx); err != nil && ctx.Err() == nil {
			logger.Error("抓包错误", "error", err)
		}
	}()

	// 启动聚合器
	wg.Add(1)
	go func() {
		defer wg.Done()
		agg.Run(ctx, capturer.Events(), capturer.Stats(), entriesChan)
	}()

	// 获取系统信息
	hostname, _ := os.Hostname()
	ifaces, _ := capture.DiscoverInterfaces(cfg.Interfaces)

	startTime := time.Now()
	var lastEntries []aggregator.TrafficEntry
	var entriesMu sync.Mutex

	// 运行 TUI 或等待导出
	if cfg.Output.NoTUI {
		// 非 TUI 模式：收集数据直到超时或退出
		for {
			select {
			case <-ctx.Done():
				goto exportData
			case entries, ok := <-entriesChan:
				if !ok {
					goto exportData
				}
				entriesMu.Lock()
				lastEntries = entries
				entriesMu.Unlock()
			}
		}
	} else {
		// TUI 模式
		tuiCfg := tui.Config{
			SupportsDirection: caps.SupportsDirection,
			Hostname:          hostname,
			KernelVersion:     getKernelVersion(),
			Interfaces:        ifaces,
		}

		// 在后台收集最后的数据用于导出
		go func() {
			for entries := range entriesChan {
				entriesMu.Lock()
				lastEntries = entries
				entriesMu.Unlock()
			}
		}()

		if err := tui.Run(tuiCfg, entriesChan); err != nil {
			cancel()
			return fmt.Errorf("TUI 错误: %w", err)
		}
		cancel()
	}

exportData:
	// 停止抓包
	capturer.Stop()
	wg.Wait()

	// 导出数据
	entriesMu.Lock()
	defer entriesMu.Unlock()

	if cfg.Output.File != "" && len(lastEntries) > 0 {
		format, err := export.ParseFormat(cfg.Output.Format)
		if err != nil {
			return err
		}

		var totalIn, totalOut uint64
		for _, e := range lastEntries {
			totalIn += e.TotalIn
			totalOut += e.TotalOut
		}

		report := &export.Report{
			Timestamp:   time.Now(),
			Duration:    time.Since(startTime),
			TotalIn:     totalIn,
			TotalOut:    totalOut,
			Connections: len(lastEntries),
			Entries:     lastEntries,
		}

		if err := export.Export(report, cfg.Output.File, format); err != nil {
			return fmt.Errorf("导出失败: %w", err)
		}
		logger.Info("数据已导出", "file", cfg.Output.File)
	}

	return nil
}

func checkPermissions() error {
	if runtime.GOOS == "linux" {
		if os.Geteuid() != 0 {
			return fmt.Errorf("需要 root 权限或 CAP_NET_ADMIN 能力")
		}
	} else if runtime.GOOS == "darwin" {
		if os.Geteuid() != 0 {
			if _, err := os.Stat("/dev/bpf0"); os.IsPermission(err) {
				return fmt.Errorf("需要 sudo 权限或加入 access_bpf 组")
			}
		}
	}
	return nil
}

func getKernelVersion() string {
	if runtime.GOOS == "darwin" {
		return "macOS"
	}
	// Linux: 读取 /proc/version
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "unknown"
	}
	parts := strings.Fields(string(data))
	if len(parts) >= 3 {
		return parts[2]
	}
	return "unknown"
}

func Execute() error {
	return rootCmd.Execute()
}
