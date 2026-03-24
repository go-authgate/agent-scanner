package mcpclient

import (
	"context"
	"fmt"

	"github.com/go-authgate/agent-scanner/internal/models"
)

// Transport is the interface for MCP communication transports.
type Transport interface {
	// Connect opens the transport connection.
	Connect(ctx context.Context) error
	// Send sends a JSON-RPC message.
	Send(ctx context.Context, msg *JSONRPCMessage) error
	// Receive returns a channel of incoming JSON-RPC messages.
	Receive() <-chan *JSONRPCMessage
	// Close shuts down the transport.
	Close() error
}

// Client creates MCP sessions from server configurations.
type Client interface {
	// Connect establishes a connection and returns a session.
	Connect(ctx context.Context, cfg models.ServerConfig, timeout int) (Session, error)
}

type client struct {
	skipSSLVerify bool
}

// NewClient creates a new MCP client.
func NewClient(skipSSLVerify bool) Client {
	return &client{skipSSLVerify: skipSSLVerify}
}

func (c *client) Connect(
	ctx context.Context,
	cfg models.ServerConfig,
	timeout int,
) (Session, error) {
	var transport Transport

	switch srv := cfg.(type) {
	case *models.StdioServer:
		transport = NewStdioTransport(srv)
	case *models.RemoteServer:
		switch srv.GetServerType() {
		case models.ServerTypeSSE:
			transport = NewSSETransport(srv, timeout, c.skipSSLVerify)
		default:
			transport = NewHTTPTransport(srv, timeout, c.skipSSLVerify)
		}
	default:
		return nil, fmt.Errorf("unsupported server type: %T", cfg)
	}

	if err := transport.Connect(ctx); err != nil {
		return nil, fmt.Errorf("connect transport: %w", err)
	}

	session := NewSession(transport)
	return session, nil
}
