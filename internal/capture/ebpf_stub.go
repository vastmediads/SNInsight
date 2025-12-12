//go:build !linux

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
	return nil, errors.New("eBPF 抓包仅支持 Linux")
}

func (c *ebpfCapturer) Start(ctx context.Context) error {
	return errors.New("eBPF 抓包仅支持 Linux")
}

func (c *ebpfCapturer) Stop() error {
	return nil
}

func (c *ebpfCapturer) Events() <-chan PacketEvent {
	return nil
}

func (c *ebpfCapturer) Stats() <-chan []FlowStats {
	return nil
}

func (c *ebpfCapturer) Capabilities() Capabilities {
	return Capabilities{}
}
