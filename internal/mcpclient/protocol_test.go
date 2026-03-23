package mcpclient

import (
	"encoding/json"
	"testing"
)

func TestNewRequest(t *testing.T) {
	req, err := NewRequest(1, "initialize", map[string]any{"key": "value"})
	if err != nil {
		t.Fatal(err)
	}

	if req.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc=2.0, got %s", req.JSONRPC)
	}
	if req.Method != "initialize" {
		t.Errorf("expected method=initialize, got %s", req.Method)
	}
	if req.ID == nil {
		t.Fatal("expected non-nil ID")
	}

	var id int
	if err := json.Unmarshal(*req.ID, &id); err != nil {
		t.Fatal(err)
	}
	if id != 1 {
		t.Errorf("expected id=1, got %d", id)
	}

	if !req.IsRequest() {
		t.Error("expected IsRequest() = true")
	}
	if req.IsResponse() {
		t.Error("expected IsResponse() = false")
	}
	if req.IsNotification() {
		t.Error("expected IsNotification() = false")
	}
}

func TestNewNotification(t *testing.T) {
	notif, err := NewNotification("notifications/initialized", nil)
	if err != nil {
		t.Fatal(err)
	}

	if notif.ID != nil {
		t.Error("expected nil ID for notification")
	}
	if !notif.IsNotification() {
		t.Error("expected IsNotification() = true")
	}
	if notif.IsRequest() {
		t.Error("expected IsRequest() = false")
	}
}

func TestJSONRPCMessageSerialization(t *testing.T) {
	req, _ := NewRequest(42, "tools/list", map[string]any{})

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	var decoded JSONRPCMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc=2.0, got %s", decoded.JSONRPC)
	}
	if decoded.Method != "tools/list" {
		t.Errorf("expected method=tools/list, got %s", decoded.Method)
	}
}

func TestIsError(t *testing.T) {
	msg := &JSONRPCMessage{
		JSONRPC: "2.0",
		Error:   &JSONRPCError{Code: -32600, Message: "Invalid Request"},
	}
	if !msg.IsError() {
		t.Error("expected IsError() = true")
	}

	msg2 := &JSONRPCMessage{JSONRPC: "2.0"}
	if msg2.IsError() {
		t.Error("expected IsError() = false")
	}
}
