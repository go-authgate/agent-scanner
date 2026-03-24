package mcpclient

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// --- mock transport --------------------------------------------------------

// mockTransport implements Transport for testing. It tracks which methods were
// called and provides controllable send/receive behaviour.
type mockTransport struct {
	mu            sync.Mutex
	connectCalled bool
	connectErr    error

	closeCalled bool
	closeErr    error

	sentMessages []*JSONRPCMessage
	sendErr      error

	recvCh chan *JSONRPCMessage
}

func newMockTransport() *mockTransport {
	return &mockTransport{
		recvCh: make(chan *JSONRPCMessage, 64),
	}
}

func (m *mockTransport) Connect(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectCalled = true
	return m.connectErr
}

func (m *mockTransport) Send(_ context.Context, msg *JSONRPCMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentMessages = append(m.sentMessages, msg)
	return m.sendErr
}

func (m *mockTransport) Receive() <-chan *JSONRPCMessage {
	return m.recvCh
}

func (m *mockTransport) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCalled = true
	return m.closeErr
}

// --- tests -----------------------------------------------------------------

func TestCaptureTransport_DelegatesConnect(t *testing.T) {
	mock := newMockTransport()
	ct := NewCaptureTransport(mock)

	if err := ct.Connect(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.connectCalled {
		t.Error("expected Connect to be delegated to inner transport")
	}
}

func TestCaptureTransport_DelegatesConnectError(t *testing.T) {
	mock := newMockTransport()
	mock.connectErr = errors.New("connect failed")
	ct := NewCaptureTransport(mock)

	err := ct.Connect(context.Background())
	if err == nil {
		t.Fatal("expected error from Connect")
	}
	if err.Error() != "connect failed" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCaptureTransport_DelegatesSend(t *testing.T) {
	mock := newMockTransport()
	ct := NewCaptureTransport(mock)

	msg := &JSONRPCMessage{JSONRPC: "2.0", Method: "test"}
	if err := ct.Send(context.Background(), msg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()
	if len(mock.sentMessages) != 1 {
		t.Fatalf("expected 1 sent message on inner transport, got %d", len(mock.sentMessages))
	}
	if mock.sentMessages[0].Method != "test" {
		t.Errorf("expected method=test, got %s", mock.sentMessages[0].Method)
	}
}

func TestCaptureTransport_DelegatesClose(t *testing.T) {
	mock := newMockTransport()
	ct := NewCaptureTransport(mock)

	if err := ct.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.closeCalled {
		t.Error("expected Close to be delegated to inner transport")
	}
}

func TestCaptureTransport_DelegatesCloseError(t *testing.T) {
	mock := newMockTransport()
	mock.closeErr = errors.New("close failed")
	ct := NewCaptureTransport(mock)

	err := ct.Close()
	if err == nil {
		t.Fatal("expected error from Close")
	}
	if err.Error() != "close failed" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCaptureTransport_CapturesSentMessages(t *testing.T) {
	mock := newMockTransport()
	ct := NewCaptureTransport(mock)

	before := time.Now()

	msg1 := &JSONRPCMessage{JSONRPC: "2.0", Method: "tools/list"}
	msg2 := &JSONRPCMessage{JSONRPC: "2.0", Method: "prompts/list"}

	if err := ct.Send(context.Background(), msg1); err != nil {
		t.Fatal(err)
	}
	if err := ct.Send(context.Background(), msg2); err != nil {
		t.Fatal(err)
	}

	after := time.Now()

	msgs := ct.Messages()
	if len(msgs) != 2 {
		t.Fatalf("expected 2 captured messages, got %d", len(msgs))
	}

	for i, cm := range msgs {
		if cm.Direction != "sent" {
			t.Errorf("message[%d]: expected direction=sent, got %s", i, cm.Direction)
		}
		if cm.Timestamp.Before(before) || cm.Timestamp.After(after) {
			t.Errorf("message[%d]: timestamp %v outside expected range", i, cm.Timestamp)
		}
	}

	if msgs[0].Message.Method != "tools/list" {
		t.Errorf("expected first message method=tools/list, got %s", msgs[0].Message.Method)
	}
	if msgs[1].Message.Method != "prompts/list" {
		t.Errorf("expected second message method=prompts/list, got %s", msgs[1].Message.Method)
	}
}

func TestCaptureTransport_CapturesReceivedMessages(t *testing.T) {
	mock := newMockTransport()
	ct := NewCaptureTransport(mock)

	// Start receiving before pushing messages into the mock channel.
	recvCh := ct.Receive()

	before := time.Now()

	resp1 := &JSONRPCMessage{JSONRPC: "2.0", Method: "notification/one"}
	resp2 := &JSONRPCMessage{JSONRPC: "2.0", Method: "notification/two"}

	mock.recvCh <- resp1
	mock.recvCh <- resp2
	close(mock.recvCh)

	// Drain the wrapped channel.
	var received []*JSONRPCMessage
	for msg := range recvCh {
		received = append(received, msg)
	}

	after := time.Now()

	if len(received) != 2 {
		t.Fatalf("expected 2 forwarded messages, got %d", len(received))
	}

	msgs := ct.Messages()
	if len(msgs) != 2 {
		t.Fatalf("expected 2 captured messages, got %d", len(msgs))
	}

	for i, cm := range msgs {
		if cm.Direction != "received" {
			t.Errorf("message[%d]: expected direction=received, got %s", i, cm.Direction)
		}
		if cm.Timestamp.Before(before) || cm.Timestamp.After(after) {
			t.Errorf("message[%d]: timestamp %v outside expected range", i, cm.Timestamp)
		}
	}

	if msgs[0].Message.Method != "notification/one" {
		t.Errorf("expected first captured method=notification/one, got %s", msgs[0].Message.Method)
	}
	if msgs[1].Message.Method != "notification/two" {
		t.Errorf("expected second captured method=notification/two, got %s", msgs[1].Message.Method)
	}
}

func TestCaptureTransport_MessagesReturnsCopy(t *testing.T) {
	mock := newMockTransport()
	ct := NewCaptureTransport(mock)

	msg := &JSONRPCMessage{JSONRPC: "2.0", Method: "test"}
	if err := ct.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}

	copy1 := ct.Messages()
	copy2 := ct.Messages()

	if len(copy1) != 1 || len(copy2) != 1 {
		t.Fatal("expected 1 message in each copy")
	}

	// Mutate the first copy and verify the second is unaffected.
	copy1[0].Direction = "mutated"

	copy3 := ct.Messages()
	if copy3[0].Direction != "sent" {
		t.Errorf(
			"expected Messages() to return independent copy; got direction=%s",
			copy3[0].Direction,
		)
	}
	if copy2[0].Direction != "sent" {
		t.Errorf("expected earlier copy to be unaffected; got direction=%s", copy2[0].Direction)
	}
}

func TestCaptureTransport_MixedSentAndReceived(t *testing.T) {
	mock := newMockTransport()
	ct := NewCaptureTransport(mock)

	// Start the receive goroutine.
	recvCh := ct.Receive()

	// Send a message.
	sendMsg := &JSONRPCMessage{JSONRPC: "2.0", Method: "request"}
	if err := ct.Send(context.Background(), sendMsg); err != nil {
		t.Fatal(err)
	}

	// Push a received message.
	recvMsg := &JSONRPCMessage{JSONRPC: "2.0", Method: "response"}
	mock.recvCh <- recvMsg
	close(mock.recvCh)

	// Drain received channel.
	for range recvCh {
	}

	msgs := ct.Messages()
	if len(msgs) != 2 {
		t.Fatalf("expected 2 captured messages, got %d", len(msgs))
	}

	// First should be the sent message.
	if msgs[0].Direction != "sent" {
		t.Errorf("expected first message direction=sent, got %s", msgs[0].Direction)
	}
	if msgs[0].Message.Method != "request" {
		t.Errorf("expected first message method=request, got %s", msgs[0].Message.Method)
	}

	// Second should be the received message.
	if msgs[1].Direction != "received" {
		t.Errorf("expected second message direction=received, got %s", msgs[1].Direction)
	}
	if msgs[1].Message.Method != "response" {
		t.Errorf("expected second message method=response, got %s", msgs[1].Message.Method)
	}
}
