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
	"sync"
	"time"

	"github.com/go-authgate/agent-scanner/internal/models"
	"github.com/go-authgate/agent-scanner/internal/tlsutil"
)

// defaultBaseTransport returns the base *http.Transport for cloning. Tests may
// override this variable to inject a custom transport without mutating the global
// http.DefaultTransport.
var defaultBaseTransport = tlsutil.CloneTransport

// onceCloser wraps an io.ReadCloser and ensures Close is called at most once,
// preventing double-close races when both a goroutine and Close() hold a reference.
type onceCloser struct {
	io.ReadCloser
	once sync.Once
	err  error
}

func (o *onceCloser) Close() error {
	o.once.Do(func() { o.err = o.ReadCloser.Close() })
	return o.err
}

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
	t := defaultBaseTransport()
	tlsutil.ApplyInsecureSkipVerify(t)
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
	slog.Debug("HTTP transport ready", "url", sanitizeURL(t.server.URL))
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
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			return fmt.Errorf("HTTP send: status %d: %s", resp.StatusCode, string(body))
		}
		// Wrap in onceCloser so the goroutine's defer and Close() can both
		// call Close() without racing on a double-close.
		sc := &onceCloser{ReadCloser: resp.Body}
		t.mu.Lock()
		prev := t.streamBody
		t.streamBody = sc
		t.mu.Unlock()
		if prev != nil {
			prev.Close()
		}
		go t.readStreamingResponse(sc)
		return nil
	}

	// Regular JSON response
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP send: status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB max
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
