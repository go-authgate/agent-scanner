package analysis

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-authgate/agent-scanner/internal/models"
)

func TestAnalyze_EmptyURL(t *testing.T) {
	requestMade := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMade = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	a := NewAnalyzer("", false)
	results := []models.ScanPathResult{
		{
			Client: "test",
			Path:   "/p",
			Servers: []models.ServerScanResult{
				{
					Name:   "srv",
					Server: &models.StdioServer{Command: "test"},
					Signature: &models.ServerSignature{
						Tools: []models.Tool{{Name: "t1", Description: "desc"}},
					},
				},
			},
		},
	}

	out, err := a.Analyze(context.Background(), results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requestMade {
		t.Error("expected no HTTP request when analysis URL is empty")
	}
	if len(out) != 1 {
		t.Errorf("expected results returned unchanged, got %d", len(out))
	}
}

func TestAnalyze_Success(t *testing.T) {
	respData := analysisResponse{
		Issues: []models.Issue{
			{Code: "E001", Message: "remote issue"},
		},
		Labels: [][]models.ScalarToolLabels{
			{{IsPublicSink: 0.9, Destructive: 0.1}},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}

		// Verify request body
		var req analysisRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		if len(req.Servers) != 1 {
			t.Errorf("expected 1 server in request, got %d", len(req.Servers))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(respData)
	}))
	defer ts.Close()

	a := NewAnalyzer(ts.URL, false)
	results := []models.ScanPathResult{
		{
			Client: "test",
			Path:   "/p",
			Servers: []models.ServerScanResult{
				{
					Name:   "srv1",
					Server: &models.StdioServer{Command: "cmd"},
					Signature: &models.ServerSignature{
						Tools: []models.Tool{
							{Name: "tool1", Description: "a tool"},
						},
					},
				},
			},
			Issues: []models.Issue{
				{Code: "W001", Message: "existing issue"},
			},
		},
	}

	out, err := a.Analyze(context.Background(), results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(out) != 1 {
		t.Fatalf("expected 1 result, got %d", len(out))
	}

	// Check that remote issues were merged in
	if len(out[0].Issues) != 2 {
		t.Fatalf("expected 2 issues (1 existing + 1 remote), got %d", len(out[0].Issues))
	}
	if out[0].Issues[0].Code != "W001" {
		t.Errorf("expected first issue code W001, got %s", out[0].Issues[0].Code)
	}
	if out[0].Issues[1].Code != "E001" {
		t.Errorf("expected second issue code E001, got %s", out[0].Issues[1].Code)
	}

	// Check labels were merged
	if len(out[0].Labels) != 1 {
		t.Fatalf("expected 1 label set, got %d", len(out[0].Labels))
	}
	if out[0].Labels[0][0].IsPublicSink != 0.9 {
		t.Errorf("expected IsPublicSink 0.9, got %f", out[0].Labels[0][0].IsPublicSink)
	}
}

func TestAnalyze_NilSignatureSkipped(t *testing.T) {
	requestMade := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMade = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(analysisResponse{})
	}))
	defer ts.Close()

	a := NewAnalyzer(ts.URL, false)
	results := []models.ScanPathResult{
		{
			Client: "test",
			Path:   "/p",
			Servers: []models.ServerScanResult{
				{
					Name:      "srv-no-sig",
					Server:    &models.StdioServer{Command: "cmd"},
					Signature: nil, // nil signature should be skipped
				},
			},
		},
	}

	out, err := a.Analyze(context.Background(), results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requestMade {
		t.Error("expected no HTTP request when all signatures are nil")
	}
	if len(out) != 1 {
		t.Errorf("expected results returned, got %d", len(out))
	}
}

func TestAnalyze_4xxNoRetry(t *testing.T) {
	var requestCount atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer ts.Close()

	a := NewAnalyzer(ts.URL, false)
	results := []models.ScanPathResult{
		{
			Client: "test",
			Path:   "/p",
			Servers: []models.ServerScanResult{
				{
					Name:   "srv",
					Server: &models.StdioServer{Command: "cmd"},
					Signature: &models.ServerSignature{
						Tools: []models.Tool{{Name: "t", Description: "d"}},
					},
				},
			},
		},
	}

	_, err := a.Analyze(context.Background(), results)
	if err != nil {
		t.Fatalf("Analyze should not return error (it logs warning instead), got: %v", err)
	}

	count := requestCount.Load()
	if count != 1 {
		t.Errorf("expected exactly 1 request (no retry on 4xx), got %d", count)
	}
}

func TestAnalyze_5xxRetries(t *testing.T) {
	var requestCount atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer ts.Close()

	a := NewAnalyzer(ts.URL, false)
	results := []models.ScanPathResult{
		{
			Client: "test",
			Path:   "/p",
			Servers: []models.ServerScanResult{
				{
					Name:   "srv",
					Server: &models.StdioServer{Command: "cmd"},
					Signature: &models.ServerSignature{
						Tools: []models.Tool{{Name: "t", Description: "d"}},
					},
				},
			},
		},
	}

	// Use a context with a deadline so we don't wait for full backoff.
	// First request is immediate, then 1s backoff, then 2s backoff.
	// With a 4s timeout we should reliably get at least 2 attempts without flakiness.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	_, err := a.Analyze(ctx, results)
	// Analyze doesn't return error even on failure (it logs a warning)
	if err != nil {
		t.Fatalf("Analyze should not return error, got: %v", err)
	}

	count := requestCount.Load()
	if count < 2 {
		t.Errorf("expected at least 2 requests (retries on 5xx), got %d", count)
	}
}

func TestAnalyze_FailureDoesNotFailOverall(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("error"))
	}))
	defer ts.Close()

	a := NewAnalyzer(ts.URL, false)
	results := []models.ScanPathResult{
		{
			Client: "test",
			Path:   "/p1",
			Servers: []models.ServerScanResult{
				{
					Name:   "srv",
					Server: &models.StdioServer{Command: "cmd"},
					Signature: &models.ServerSignature{
						Tools: []models.Tool{{Name: "t", Description: "d"}},
					},
				},
			},
			Issues: []models.Issue{
				{Code: "W001", Message: "existing"},
			},
		},
	}

	out, err := a.Analyze(context.Background(), results)
	if err != nil {
		t.Fatalf("expected no error from Analyze even when analysis fails, got: %v", err)
	}

	// Results should still be returned
	if len(out) != 1 {
		t.Fatalf("expected 1 result, got %d", len(out))
	}
	// Existing issues should be preserved
	if len(out[0].Issues) != 1 {
		t.Errorf("expected existing issues preserved, got %d", len(out[0].Issues))
	}
}

func TestAnalyze_AllNilSignatures(t *testing.T) {
	requestMade := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMade = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(analysisResponse{})
	}))
	defer ts.Close()

	a := NewAnalyzer(ts.URL, false)
	results := []models.ScanPathResult{
		{
			Client: "test",
			Path:   "/p",
			Servers: []models.ServerScanResult{
				{
					Name:      "srv1",
					Server:    &models.StdioServer{Command: "cmd1"},
					Signature: nil,
				},
				{
					Name:      "srv2",
					Server:    &models.StdioServer{Command: "cmd2"},
					Signature: nil,
				},
			},
		},
	}

	out, err := a.Analyze(context.Background(), results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requestMade {
		t.Error("expected no HTTP request when all signatures are nil")
	}
	if len(out) != 1 {
		t.Errorf("expected results returned unchanged, got %d", len(out))
	}
}
