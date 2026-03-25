package tlsutil

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestCloneTransport_ReturnsNonNil(t *testing.T) {
	tr := CloneTransport()
	if tr == nil {
		t.Fatal("CloneTransport() returned nil")
	}
}

func TestCloneTransport_ReturnsSeparateInstance(t *testing.T) {
	tr := CloneTransport()
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Skip("http.DefaultTransport is not *http.Transport; cannot compare pointers")
	}
	if tr == base {
		t.Fatal("CloneTransport() returned the same pointer as http.DefaultTransport")
	}
}

func TestCloneTransport_HasExpectedDefaults(t *testing.T) {
	tr := CloneTransport()

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Skip("http.DefaultTransport is not *http.Transport; cannot compare defaults")
	}

	if tr.MaxIdleConns != base.MaxIdleConns {
		t.Errorf("MaxIdleConns = %d, want %d", tr.MaxIdleConns, base.MaxIdleConns)
	}
	if tr.IdleConnTimeout != base.IdleConnTimeout {
		t.Errorf("IdleConnTimeout = %v, want %v", tr.IdleConnTimeout, base.IdleConnTimeout)
	}
	if tr.TLSHandshakeTimeout != base.TLSHandshakeTimeout {
		t.Errorf(
			"TLSHandshakeTimeout = %v, want %v",
			tr.TLSHandshakeTimeout, base.TLSHandshakeTimeout,
		)
	}
	if tr.ForceAttemptHTTP2 != base.ForceAttemptHTTP2 {
		t.Errorf("ForceAttemptHTTP2 = %v, want %v", tr.ForceAttemptHTTP2, base.ForceAttemptHTTP2)
	}
}

func TestApplyInsecureSkipVerify_NilTLSConfig(t *testing.T) {
	tr := &http.Transport{}
	if tr.TLSClientConfig != nil {
		t.Fatal("precondition failed: TLSClientConfig should be nil")
	}

	ApplyInsecureSkipVerify(tr)

	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is still nil after ApplyInsecureSkipVerify")
	}
	if !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want true")
	}
}

func TestApplyInsecureSkipVerify_ExistingTLSConfig(t *testing.T) {
	original := &tls.Config{
		ServerName: "example.com",
		MinVersion: tls.VersionTLS12,
	}
	tr := &http.Transport{
		TLSClientConfig: original,
	}

	ApplyInsecureSkipVerify(tr)

	// Must not mutate the original config.
	if original.InsecureSkipVerify {
		t.Error("original tls.Config was mutated; InsecureSkipVerify should still be false")
	}

	// The transport must have a new config.
	if tr.TLSClientConfig == original {
		t.Error("TLSClientConfig is the same pointer as the original; should be a clone")
	}

	// New config must have InsecureSkipVerify set.
	if !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false on new config, want true")
	}

	// Cloned config should preserve existing fields.
	if tr.TLSClientConfig.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want %q", tr.TLSClientConfig.ServerName, "example.com")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d", tr.TLSClientConfig.MinVersion, tls.VersionTLS12)
	}
}
