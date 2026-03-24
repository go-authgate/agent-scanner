package mcpclient

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/go-authgate/agent-scanner/internal/models"
)

func TestNewHTTPClient_DefaultTransport(t *testing.T) {
	client := newHTTPClient(5*time.Second, false)
	if client.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", client.Timeout)
	}
	// Should use the shared default transport (nil means default).
	if client.Transport != nil {
		t.Error("expected nil transport (shared default) when skipSSLVerify=false")
	}
}

func TestNewHTTPClient_SkipSSLVerify(t *testing.T) {
	client := newHTTPClient(10*time.Second, true)
	if client.Timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", client.Timeout)
	}

	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport when skipSSLVerify=true")
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("expected non-nil TLSClientConfig")
	}
	if !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true")
	}
}

// TestNewHTTPTransport_SkipSSLVerify verifies that NewHTTPTransport correctly
// configures the httpClient TLS transport based on the skipSSLVerify flag.
func TestNewHTTPTransport_SkipSSLVerify(t *testing.T) {
	server := &models.RemoteServer{URL: "http://localhost:9999"}

	// skipSSLVerify=false: should use shared default transport (nil).
	tr := NewHTTPTransport(server, 10, false).(*httpTransport)
	if tr.httpClient.Transport != nil {
		t.Error("expected nil transport when skipSSLVerify=false")
	}

	// skipSSLVerify=true: should have InsecureSkipVerify set.
	tr = NewHTTPTransport(server, 10, true).(*httpTransport)
	httpTr, ok := tr.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport when skipSSLVerify=true")
	}
	if httpTr.TLSClientConfig == nil || !httpTr.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true on HTTP transport")
	}
}

// TestNewSSETransport_SkipSSLVerify verifies that NewSSETransport correctly
// configures the httpClient TLS transport based on the skipSSLVerify flag.
func TestNewSSETransport_SkipSSLVerify(t *testing.T) {
	server := &models.RemoteServer{URL: "http://localhost:9999", Type: models.ServerTypeSSE}

	// skipSSLVerify=false: should use shared default transport (nil).
	tr := NewSSETransport(server, 10, false).(*sseTransport)
	if tr.httpClient.Transport != nil {
		t.Error("expected nil transport when skipSSLVerify=false")
	}

	// skipSSLVerify=true: should have InsecureSkipVerify set.
	tr = NewSSETransport(server, 10, true).(*sseTransport)
	httpTr, ok := tr.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport when skipSSLVerify=true")
	}
	if httpTr.TLSClientConfig == nil || !httpTr.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true on SSE transport")
	}
}

func TestNewHTTPClient_SkipSSLVerify_PreservesExistingTLSConfig(t *testing.T) {
	// Override the package-level getter instead of mutating http.DefaultTransport,
	// which would be unsafe due to cross-test/goroutine interference within
	// the same test binary.
	orig := defaultBaseTransport
	defaultBaseTransport = func() *http.Transport {
		return &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		}
	}
	defer func() { defaultBaseTransport = orig }()

	client := newHTTPClient(5*time.Second, true)

	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("expected non-nil TLSClientConfig")
	}
	if !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Error("expected MinVersion to be preserved from existing TLS config")
	}
}
