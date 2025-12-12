package main

import (
	"fmt"
	"os"

	"github.com/nickproject/sninsight/internal/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// TODO: 实现主逻辑
	_ = config.Default()
	fmt.Println("Sninsight - 网络流量监控工具")
	return nil
}
