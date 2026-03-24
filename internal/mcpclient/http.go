package mcpclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-authgate/agent-scanner/internal/models"
)

type httpTransport struct {
	server     *models.RemoteServer
	timeout    int
	httpClient *http.Client
	recvCh     chan *JSONRPCMessage
	sessionID  string
	mu         sync.Mutex
	streamBody io.Closer
}

// newHTTPClient builds an http.Client. When skipSSLVerify is false the shared
// default transport is used to maximise connection reuse. When true, the
// default transport is cloned and TLS certificate verification is disabled.
func newHTTPClient(timeout time.Duration, skipSSLVerify bool) *http.Client {
	if !skipSSLVerify {
		return &http.Client{Timeout: timeout}
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// DefaultTransport has been replaced with a non-*http.Transport; construct
		// a new one that preserves Go's standard defaults (proxy, dialer, timeouts).
		base = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
		}
	}
	t := base.Clone()
	if t.TLSClientConfig != nil {
		cfg := t.TLSClientConfig.Clone()
		cfg.InsecureSkipVerify = true //nolint:gosec // controlled by --skip-ssl-verify flag, user opt-in
		t.TLSClientConfig = cfg
	} else {
		t.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // controlled by --skip-ssl-verify flag, user opt-in
		}
	}
	return &http.Client{Timeout: timeout, Transport: t}
}

// NewHTTPTransport creates a transport using streamable HTTP.
func NewHTTPTransport(server *models.RemoteServer, timeout int, skipSSLVerify bool) Transport {
	return &httpTransport{
		server:     server,
		timeout:    timeout,
		httpClient: newHTTPClient(time.Duration(timeout*3)*time.Second, skipSSLVerify),
		recvCh:     make(chan *JSONRPCMessage, 64),
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
		if resp.StatusCode >= 400 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return fmt.Errorf("HTTP send: status %d: %s", resp.StatusCode, string(body))
		}
		// Streaming response — track body under lock so Close() can stop it.
		t.mu.Lock()
		prev := t.streamBody
		t.streamBody = resp.Body
		t.mu.Unlock()
		if prev != nil {
			prev.Close()
		}
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
	t.mu.Lock()
	body := t.streamBody
	t.streamBody = nil
	t.mu.Unlock()
	if body != nil {
		body.Close()
	}
	if tr, ok := t.httpClient.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
	return nil
}
