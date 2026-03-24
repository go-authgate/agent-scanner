package mcpclient

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"
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

func TestNewHTTPClient_SkipSSLVerify_PreservesExistingTLSConfig(t *testing.T) {
	// Temporarily replace DefaultTransport with one that has existing TLS settings.
	orig := http.DefaultTransport
	custom := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	http.DefaultTransport = custom
	defer func() { http.DefaultTransport = orig }()

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
