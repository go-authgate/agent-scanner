package mcpclient

import (
	"context"
	"encoding/json"
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
		Message:   cloneJSONRPCMessage(msg),
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
				Message:   cloneJSONRPCMessage(msg),
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

// cloneJSONRPCMessage returns a deep copy of a JSONRPCMessage so that
// later mutations by callers or the inner transport do not affect captured data.
func cloneJSONRPCMessage(msg *JSONRPCMessage) *JSONRPCMessage {
	if msg == nil {
		return nil
	}
	c := *msg
	c.Params = cloneRawMessage(msg.Params)
	c.Result = cloneRawMessage(msg.Result)
	if msg.ID != nil {
		id := cloneRawMessage(*msg.ID)
		c.ID = &id
	}
	if msg.Error != nil {
		errCopy := *msg.Error
		errCopy.Data = cloneRawMessage(msg.Error.Data)
		c.Error = &errCopy
	}
	return &c
}

// cloneRawMessage returns a copy of a json.RawMessage byte slice.
func cloneRawMessage(raw json.RawMessage) json.RawMessage {
	if raw == nil {
		return nil
	}
	cp := make(json.RawMessage, len(raw))
	copy(cp, raw)
	return cp
}
