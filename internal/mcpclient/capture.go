package mcpclient

import (
	"context"
	"encoding/json"
	"sync"
)

// TrafficCapture records MCP protocol messages for debugging.
type TrafficCapture struct {
	mu       sync.Mutex
	Sent     []json.RawMessage
	Received []json.RawMessage
	Stderr   []string
}

// NewTrafficCapture creates a new traffic capture.
func NewTrafficCapture() *TrafficCapture {
	return &TrafficCapture{}
}

// RecordSent records an outbound message.
func (tc *TrafficCapture) RecordSent(msg *JSONRPCMessage) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	data, _ := json.Marshal(msg)
	tc.Sent = append(tc.Sent, data)
}

// RecordReceived records an inbound message.
func (tc *TrafficCapture) RecordReceived(msg *JSONRPCMessage) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	data, _ := json.Marshal(msg)
	tc.Received = append(tc.Received, data)
}

// capturingTransport wraps a transport to capture traffic.
type capturingTransport struct {
	inner   Transport
	capture *TrafficCapture
}

// NewCapturingTransport wraps a transport with traffic capture.
func NewCapturingTransport(inner Transport, capture *TrafficCapture) Transport {
	return &capturingTransport{inner: inner, capture: capture}
}

func (t *capturingTransport) Connect(ctx context.Context) error {
	return t.inner.Connect(ctx)
}

func (t *capturingTransport) Send(ctx context.Context, msg *JSONRPCMessage) error {
	t.capture.RecordSent(msg)
	return t.inner.Send(ctx, msg)
}

func (t *capturingTransport) Receive() <-chan *JSONRPCMessage {
	// Wrap the receive channel to capture messages
	innerCh := t.inner.Receive()
	wrappedCh := make(chan *JSONRPCMessage, 64)
	go func() {
		defer close(wrappedCh)
		for msg := range innerCh {
			t.capture.RecordReceived(msg)
			wrappedCh <- msg
		}
	}()
	return wrappedCh
}

func (t *capturingTransport) Close() error {
	return t.inner.Close()
}
