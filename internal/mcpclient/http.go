package mcpclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-authgate/agent-scanner/internal/models"
)

type httpTransport struct {
	server     *models.RemoteServer
	timeout    int
	httpClient *http.Client
	recvCh     chan *JSONRPCMessage
	sessionID  string
}

// NewHTTPTransport creates a transport using streamable HTTP.
func NewHTTPTransport(server *models.RemoteServer, timeout int) Transport {
	return &httpTransport{
		server:  server,
		timeout: timeout,
		httpClient: &http.Client{
			Timeout: time.Duration(timeout*3) * time.Second,
		},
		recvCh: make(chan *JSONRPCMessage, 64),
	}
}

func (t *httpTransport) Connect(_ context.Context) error {
	slog.Debug("HTTP transport ready", "url", t.server.URL)
	return nil
}

func (t *httpTransport) Send(ctx context.Context, msg *JSONRPCMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		t.server.URL,
		bytes.NewReader(data),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range t.server.Headers {
		req.Header.Set(k, v)
	}
	if t.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", t.sessionID)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP send: %w", err)
	}

	// Store session ID if provided
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		t.sessionID = sid
	}

	contentType := resp.Header.Get("Content-Type")

	if strings.Contains(contentType, "text/event-stream") {
		// Streaming response — read SSE events
		go t.readStreamingResponse(resp.Body)
		return nil
	}

	// Regular JSON response
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP send: status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if len(body) == 0 {
		return nil
	}

	var respMsg JSONRPCMessage
	if err := json.Unmarshal(body, &respMsg); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}
	t.recvCh <- &respMsg

	return nil
}

func (t *httpTransport) readStreamingResponse(body io.ReadCloser) {
	defer body.Close()

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var data strings.Builder

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			if data.Len() > 0 {
				var msg JSONRPCMessage
				if err := json.Unmarshal([]byte(data.String()), &msg); err == nil {
					t.recvCh <- &msg
				}
				data.Reset()
			}
			continue
		}

		if strings.HasPrefix(line, "data:") {
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
}

func (t *httpTransport) Receive() <-chan *JSONRPCMessage {
	return t.recvCh
}

func (t *httpTransport) Close() error {
	return nil
}
