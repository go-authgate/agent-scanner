package mcpclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-authgate/agent-scanner/internal/models"
)

type sseTransport struct {
	server     *models.RemoteServer
	timeout    int
	httpClient *http.Client
	recvCh     chan *JSONRPCMessage
	messageURL string
	cancel     context.CancelFunc
}

// NewSSETransport creates a transport that uses Server-Sent Events.
func NewSSETransport(server *models.RemoteServer, timeout int, skipSSLVerify bool) Transport {
	return &sseTransport{
		server:     server,
		timeout:    timeout,
		httpClient: newHTTPClient(time.Duration(timeout)*time.Second, skipSSLVerify),
		recvCh:     make(chan *JSONRPCMessage, 64),
	}
}

func (t *sseTransport) Connect(ctx context.Context) error {
	ctx, t.cancel = context.WithCancel(ctx)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.server.URL, nil)
	if err != nil {
		return fmt.Errorf("create SSE request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	for k, v := range t.server.Headers {
		req.Header.Set(k, v)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("SSE connect: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return fmt.Errorf("SSE connect: status %d", resp.StatusCode)
	}

	go t.readSSE(resp.Body)

	slog.Debug("SSE transport connected", "url", sanitizeURL(t.server.URL))
	return nil
}

func (t *sseTransport) readSSE(body io.ReadCloser) {
	defer body.Close()
	defer close(t.recvCh)

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var eventType string
	var data strings.Builder

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			// Empty line = end of event
			if data.Len() > 0 {
				t.handleSSEEvent(eventType, data.String())
				eventType = ""
				data.Reset()
			}
			continue
		}

		if after, found := strings.CutPrefix(line, "event:"); found {
			eventType = strings.TrimSpace(after)
		} else if strings.HasPrefix(line, "data:") {
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
}

// resolveEndpointURL resolves and validates an endpoint URL received from an SSE
// server. Absolute URLs must share the same origin (scheme+host) as the base
// server URL to prevent SSRF. Relative URLs are resolved against the base.
func resolveEndpointURL(baseURL, endpoint string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base URL: %w", err)
	}

	ep, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse endpoint URL: %w", err)
	}

	resolved := base.ResolveReference(ep)

	// Validate same origin (scheme + host)
	if resolved.Scheme != base.Scheme || resolved.Host != base.Host {
		return "", fmt.Errorf(
			"endpoint origin %s://%s does not match server origin %s://%s",
			resolved.Scheme, resolved.Host, base.Scheme, base.Host,
		)
	}

	return resolved.String(), nil
}

func (t *sseTransport) handleSSEEvent(eventType, data string) {
	switch eventType {
	case "endpoint":
		resolved, err := resolveEndpointURL(t.server.URL, data)
		if err != nil {
			slog.Warn("rejecting SSE endpoint", "error", err, "endpoint", data)
			return
		}
		t.messageURL = resolved
		slog.Debug("SSE endpoint received", "url", sanitizeURL(t.messageURL))
	case "message", "":
		var msg JSONRPCMessage
		if err := json.Unmarshal([]byte(data), &msg); err != nil {
			slog.Debug("failed to parse SSE message", "error", err)
			return
		}
		t.recvCh <- &msg
	}
}

func (t *sseTransport) Send(ctx context.Context, msg *JSONRPCMessage) error {
	if t.messageURL == "" {
		return errors.New("no message endpoint received from SSE server")
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		t.messageURL,
		bytes.NewReader(data),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range t.server.Headers {
		req.Header.Set(k, v)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("SSE send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("SSE send: status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (t *sseTransport) Receive() <-chan *JSONRPCMessage {
	return t.recvCh
}

func (t *sseTransport) Close() error {
	if t.cancel != nil {
		t.cancel()
	}
	if tr, ok := t.httpClient.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
	return nil
}
