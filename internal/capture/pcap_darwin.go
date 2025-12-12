//go:build darwin

package capture

import (
	"context"
	"errors"
)

type pcapCapturer struct {
	cfg    CaptureConfig
	events chan PacketEvent
	stats  chan []FlowStats
}

func newPcapCapturer(cfg CaptureConfig) (*pcapCapturer, error) {
	return &pcapCapturer{
		cfg:    cfg,
		events: make(chan PacketEvent, 1000),
		stats:  make(chan []FlowStats, 10),
	}, nil
}

func (c *pcapCapturer) Start(ctx context.Context) error {
	// TODO: 实现 libpcap 抓包
	return errors.New("libpcap 抓包尚未实现")
}

func (c *pcapCapturer) Stop() error {
	close(c.events)
	close(c.stats)
	return nil
}

func (c *pcapCapturer) Events() <-chan PacketEvent {
	return c.events
}

func (c *pcapCapturer) Stats() <-chan []FlowStats {
	return c.stats
}

func (c *pcapCapturer) Capabilities() Capabilities {
	return Capabilities{
		SupportsDirection: false, // macOS 不支持方向区分
		SupportsBPFFilter: true,
	}
}
