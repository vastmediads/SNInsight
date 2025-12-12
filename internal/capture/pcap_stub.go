//go:build !darwin

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
	return nil, errors.New("pcap 抓包仅支持 macOS")
}

func (c *pcapCapturer) Start(ctx context.Context) error {
	return errors.New("pcap 抓包仅支持 macOS")
}

func (c *pcapCapturer) Stop() error {
	return nil
}

func (c *pcapCapturer) Events() <-chan PacketEvent {
	return nil
}

func (c *pcapCapturer) Stats() <-chan []FlowStats {
	return nil
}

func (c *pcapCapturer) Capabilities() Capabilities {
	return Capabilities{}
}
