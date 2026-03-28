package testserver

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

// jsonRPCMessage is a minimal JSON-RPC 2.0 message used by test servers.
type jsonRPCMessage struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *jsonRPCError    `json:"error,omitempty"`
}

// jsonRPCError is a JSON-RPC 2.0 error object.
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// makeResponse creates a JSON-RPC 2.0 success response.
func makeResponse(id *json.RawMessage, result any) *jsonRPCMessage {
	raw, _ := json.Marshal(result)
	return &jsonRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Result:  raw,
	}
}

// makeErrorResponse creates a JSON-RPC 2.0 error response.
func makeErrorResponse(id *json.RawMessage, code int, message string) *jsonRPCMessage {
	return &jsonRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error: &jsonRPCError{
			Code:    code,
			Message: message,
		},
	}
}

// runServer reads JSON-RPC messages from stdin and dispatches them to handler.
func runServer(handler func(*jsonRPCMessage) *jsonRPCMessage) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var msg jsonRPCMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}

		resp := handler(&msg)
		if resp == nil {
			continue
		}

		data, err := json.Marshal(resp)
		if err != nil {
			continue
		}
		fmt.Fprintln(os.Stdout, string(data))
	}
}
