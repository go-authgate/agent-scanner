package mcpclient

import "encoding/json"

// JSONRPCMessage represents a JSON-RPC 2.0 message.
type JSONRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError represents a JSON-RPC 2.0 error.
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// NewRequest creates a JSON-RPC 2.0 request.
func NewRequest(id int, method string, params any) (*JSONRPCMessage, error) {
	rawID, err := json.Marshal(id)
	if err != nil {
		return nil, err
	}
	idMsg := json.RawMessage(rawID)

	var rawParams json.RawMessage
	if params != nil {
		rawParams, err = json.Marshal(params)
		if err != nil {
			return nil, err
		}
	}

	return &JSONRPCMessage{
		JSONRPC: "2.0",
		ID:      &idMsg,
		Method:  method,
		Params:  rawParams,
	}, nil
}

// NewNotification creates a JSON-RPC 2.0 notification (no id).
func NewNotification(method string, params any) (*JSONRPCMessage, error) {
	var rawParams json.RawMessage
	if params != nil {
		var err error
		rawParams, err = json.Marshal(params)
		if err != nil {
			return nil, err
		}
	}

	return &JSONRPCMessage{
		JSONRPC: "2.0",
		Method:  method,
		Params:  rawParams,
	}, nil
}

// IsResponse returns true if this is a response message.
func (m *JSONRPCMessage) IsResponse() bool {
	return m.ID != nil && m.Method == ""
}

// IsRequest returns true if this is a request message.
func (m *JSONRPCMessage) IsRequest() bool {
	return m.ID != nil && m.Method != ""
}

// IsNotification returns true if this is a notification message.
func (m *JSONRPCMessage) IsNotification() bool {
	return m.ID == nil && m.Method != ""
}

// IsError returns true if this is an error response.
func (m *JSONRPCMessage) IsError() bool {
	return m.Error != nil
}
