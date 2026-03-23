package mcpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-authgate/agent-scanner/internal/models"
)

// Session represents an initialized MCP session.
type Session interface {
	Initialize(ctx context.Context) (*models.InitializeResult, error)
	ListTools(ctx context.Context) ([]models.Tool, error)
	ListPrompts(ctx context.Context) ([]models.Prompt, error)
	ListResources(ctx context.Context) ([]models.Resource, error)
	ListResourceTemplates(ctx context.Context) ([]models.ResourceTemplate, error)
	Close() error
}

type session struct {
	transport Transport
	nextID    atomic.Int64
	pending   map[int]chan *JSONRPCMessage
	mu        sync.Mutex
	done      chan struct{}
}

// NewSession creates a new MCP session from a connected transport.
func NewSession(transport Transport) Session {
	s := &session{
		transport: transport,
		pending:   make(map[int]chan *JSONRPCMessage),
		done:      make(chan struct{}),
	}
	go s.readLoop()
	return s
}

func (s *session) readLoop() {
	ch := s.transport.Receive()
	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				close(s.done)
				return
			}
			if msg.IsResponse() && msg.ID != nil {
				var id int
				if err := json.Unmarshal(*msg.ID, &id); err == nil {
					s.mu.Lock()
					if ch, ok := s.pending[id]; ok {
						ch <- msg
						delete(s.pending, id)
					}
					s.mu.Unlock()
				}
			}
		case <-s.done:
			return
		}
	}
}

func (s *session) call(ctx context.Context, method string, params any) (*JSONRPCMessage, error) {
	id := int(s.nextID.Add(1))
	req, err := NewRequest(id, method, params)
	if err != nil {
		return nil, err
	}

	respCh := make(chan *JSONRPCMessage, 1)
	s.mu.Lock()
	s.pending[id] = respCh
	s.mu.Unlock()

	if err := s.transport.Send(ctx, req); err != nil {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return nil, fmt.Errorf("send %s: %w", method, err)
	}

	select {
	case resp := <-respCh:
		if resp.IsError() {
			return nil, fmt.Errorf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)
		}
		return resp, nil
	case <-ctx.Done():
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return nil, ctx.Err()
	case <-time.After(30 * time.Second):
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return nil, fmt.Errorf("timeout waiting for %s response", method)
	}
}

func (s *session) Initialize(ctx context.Context) (*models.InitializeResult, error) {
	params := map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "agent-scanner",
			"version": "1.0.0",
		},
	}

	resp, err := s.call(ctx, "initialize", params)
	if err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}

	var result models.InitializeResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("unmarshal initialize result: %w", err)
	}

	// Send initialized notification
	notif, err := NewNotification("notifications/initialized", nil)
	if err != nil {
		return nil, err
	}
	if err := s.transport.Send(ctx, notif); err != nil {
		return nil, fmt.Errorf("send initialized notification: %w", err)
	}

	return &result, nil
}

func (s *session) ListTools(ctx context.Context) ([]models.Tool, error) {
	return listPaginated[models.Tool](ctx, s, "tools/list")
}

func (s *session) ListPrompts(ctx context.Context) ([]models.Prompt, error) {
	return listPaginated[models.Prompt](ctx, s, "prompts/list")
}

func (s *session) ListResources(ctx context.Context) ([]models.Resource, error) {
	return listPaginated[models.Resource](ctx, s, "resources/list")
}

func (s *session) ListResourceTemplates(ctx context.Context) ([]models.ResourceTemplate, error) {
	return listPaginated[models.ResourceTemplate](ctx, s, "resources/templates/list")
}

// listPaginated handles cursor-based pagination for MCP list methods.
func listPaginated[T any](ctx context.Context, s *session, method string) ([]T, error) {
	var all []T
	var cursor string

	for {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}

		resp, err := s.call(ctx, method, params)
		if err != nil {
			return all, err
		}

		// Determine the result key from the method name
		var result struct {
			Items      json.RawMessage `json:"tools"`
			Prompts    json.RawMessage `json:"prompts"`
			Resources  json.RawMessage `json:"resources"`
			Templates  json.RawMessage `json:"resourceTemplates"`
			NextCursor string          `json:"nextCursor"`
		}
		if err := json.Unmarshal(resp.Result, &result); err != nil {
			return all, fmt.Errorf("unmarshal %s result: %w", method, err)
		}

		// Select the right field based on method
		var raw json.RawMessage
		switch method {
		case "tools/list":
			raw = result.Items
		case "prompts/list":
			raw = result.Prompts
		case "resources/list":
			raw = result.Resources
		case "resources/templates/list":
			raw = result.Templates
		}

		if raw != nil {
			var items []T
			if err := json.Unmarshal(raw, &items); err != nil {
				return all, fmt.Errorf("unmarshal items: %w", err)
			}
			all = append(all, items...)
		}

		if result.NextCursor == "" {
			break
		}
		cursor = result.NextCursor
	}

	return all, nil
}

func (s *session) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return s.transport.Close()
}
