package mcpclient

import (
	"context"
	"sync"
	"time"
)

// CapturedMessage represents a captured JSON-RPC message.
type CapturedMessage struct {
	Direction string          // "sent" or "received"
	Timestamp time.Time       // when the message was captured
	Message   *JSONRPCMessage // the captured message
}

// CaptureTransport wraps a Transport and records all sent/received messages.
type CaptureTransport struct {
	inner    Transport
	messages []CapturedMessage
	mu       sync.Mutex
}

// NewCaptureTransport wraps an existing transport with message capture.
func NewCaptureTransport(inner Transport) *CaptureTransport {
	return &CaptureTransport{
		inner: inner,
	}
}

// Connect delegates to the inner transport.
func (t *CaptureTransport) Connect(ctx context.Context) error {
	return t.inner.Connect(ctx)
}

// Send captures the message then delegates to the inner transport.
func (t *CaptureTransport) Send(ctx context.Context, msg *JSONRPCMessage) error {
	t.mu.Lock()
	t.messages = append(t.messages, CapturedMessage{
		Direction: "sent",
		Timestamp: time.Now(),
		Message:   msg,
	})
	t.mu.Unlock()

	return t.inner.Send(ctx, msg)
}

// Receive returns a channel that captures messages as they arrive.
// It wraps the inner transport's receive channel with a goroutine that
// records each message before forwarding it.
func (t *CaptureTransport) Receive() <-chan *JSONRPCMessage {
	innerCh := t.inner.Receive()
	wrappedCh := make(chan *JSONRPCMessage, 64)
	go func() {
		defer close(wrappedCh)
		for msg := range innerCh {
			t.mu.Lock()
			t.messages = append(t.messages, CapturedMessage{
				Direction: "received",
				Timestamp: time.Now(),
				Message:   msg,
			})
			t.mu.Unlock()
			wrappedCh <- msg
		}
	}()
	return wrappedCh
}

// Close delegates to the inner transport.
func (t *CaptureTransport) Close() error {
	return t.inner.Close()
}

// Messages returns a copy of all captured messages.
func (t *CaptureTransport) Messages() []CapturedMessage {
	t.mu.Lock()
	defer t.mu.Unlock()

	cp := make([]CapturedMessage, len(t.messages))
	copy(cp, t.messages)
	return cp
}
