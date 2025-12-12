//go:build linux

package capture

import (
	"context"
	"errors"
)

type ebpfCapturer struct {
	cfg    CaptureConfig
	events chan PacketEvent
	stats  chan []FlowStats
}

func newEBPFCapturer(cfg CaptureConfig) (*ebpfCapturer, error) {
	return &ebpfCapturer{
		cfg:    cfg,
		events: make(chan PacketEvent, 1000),
		stats:  make(chan []FlowStats, 10),
	}, nil
}

func (c *ebpfCapturer) Start(ctx context.Context) error {
	// TODO: 实现 eBPF 抓包
	return errors.New("eBPF 抓包尚未实现")
}

func (c *ebpfCapturer) Stop() error {
	close(c.events)
	close(c.stats)
	return nil
}

func (c *ebpfCapturer) Events() <-chan PacketEvent {
	return c.events
}

func (c *ebpfCapturer) Stats() <-chan []FlowStats {
	return c.stats
}

func (c *ebpfCapturer) Capabilities() Capabilities {
	return Capabilities{
		SupportsDirection: true,
		SupportsBPFFilter: true,
	}
}
