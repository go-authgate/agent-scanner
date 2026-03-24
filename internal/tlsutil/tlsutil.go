// Package tlsutil provides shared HTTP transport helpers for consistent TLS
// configuration across MCP client and analysis HTTP clients.
package tlsutil

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// CloneTransport returns a cloned *http.Transport based on http.DefaultTransport.
// If DefaultTransport has been replaced with a non-*http.Transport, a new transport
// with Go's standard defaults (proxy, dialer timeouts, HTTP/2) is returned instead.
func CloneTransport() *http.Transport {
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		return base.Clone()
	}
	// DefaultTransport was replaced; preserve standard defaults.
	return &http.Transport{
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

// ApplyInsecureSkipVerify sets InsecureSkipVerify on t's TLS config, cloning any
// existing TLS config first to avoid mutating shared state.
func ApplyInsecureSkipVerify(t *http.Transport) {
	if t.TLSClientConfig != nil {
		cfg := t.TLSClientConfig.Clone()
		cfg.InsecureSkipVerify = true //nolint:gosec // controlled by --skip-ssl-verify flag, user opt-in
		t.TLSClientConfig = cfg
	} else {
		t.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // controlled by --skip-ssl-verify flag, user opt-in
		}
	}
}
