package capture

import (
	"context"
	"runtime"
)

// Capturer 抓包器接口
type Capturer interface {
	// Start 启动抓包，阻塞直到 ctx 取消或出错
	Start(ctx context.Context) error
	// Stop 停止抓包
	Stop() error
	// Events 返回数据包事件通道 (仅 TLS ClientHello)
	Events() <-chan PacketEvent
	// Stats 返回流量统计通道 (定时聚合)
	Stats() <-chan []FlowStats
	// Capabilities 返回平台能力
	Capabilities() Capabilities
}

// CaptureConfig 抓包配置
type CaptureConfig struct {
	Interfaces []string // 网卡列表，nil 表示所有
	BPFFilter  string   // BPF 过滤表达式
}

// New 根据平台创建 Capturer
func New(cfg CaptureConfig) (Capturer, error) {
	switch runtime.GOOS {
	case "linux":
		return newEBPFCapturer(cfg)
	case "darwin":
		return newPcapCapturer(cfg)
	default:
		return nil, &ErrUnsupportedPlatform{Platform: runtime.GOOS}
	}
}

// ErrUnsupportedPlatform 不支持的平台错误
type ErrUnsupportedPlatform struct {
	Platform string
}

func (e *ErrUnsupportedPlatform) Error() string {
	return "不支持的平台: " + e.Platform
}
