package testserver

// RunMathServer runs a test MCP server with basic math tools.
// It communicates via stdin/stdout JSON-RPC 2.0.
func RunMathServer() {
	runServer(handleMathMessage)
}

func handleMathMessage(msg *jsonRPCMessage) *jsonRPCMessage {
	switch msg.Method {
	case "initialize":
		return makeResponse(msg.ID, map[string]any{
			"protocolVersion": "2024-11-05",
			"serverInfo": map[string]any{
				"name":    "math-server",
				"version": "1.0.0",
			},
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
		})
	case "notifications/initialized":
		return nil
	case "tools/list":
		return makeResponse(msg.ID, map[string]any{
			"tools": []map[string]any{
				{
					"name":        "add",
					"description": "Add two numbers",
					"inputSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"a": map[string]any{"type": "number"},
							"b": map[string]any{"type": "number"},
						},
					},
				},
				{
					"name":        "multiply",
					"description": "Multiply two numbers",
					"inputSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"a": map[string]any{"type": "number"},
							"b": map[string]any{"type": "number"},
						},
					},
				},
			},
		})
	default:
		return makeErrorResponse(msg.ID, -32601, "Method not found")
	}
}
