package upload

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-authgate/agent-scanner/internal/httperrors"
	"github.com/go-authgate/agent-scanner/internal/models"
)

func TestUpload_Success(t *testing.T) {
	var receivedBody models.ScanPathResultsCreate

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&receivedBody); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	u := NewUploader()
	results := []models.ScanPathResult{
		{
			Client: "test-client",
			Path:   "/test/path",
			Issues: []models.Issue{
				{Code: "E001", Message: "test issue"},
			},
		},
	}
	server := models.ControlServer{
		URL:        ts.URL,
		Identifier: "test-id",
	}

	err := u.Upload(context.Background(), results, server)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(receivedBody.ScanPathResults) != 1 {
		t.Fatalf("expected 1 scan path result, got %d", len(receivedBody.ScanPathResults))
	}
	if receivedBody.ScanPathResults[0].Client != "test-client" {
		t.Errorf("expected client 'test-client', got %q", receivedBody.ScanPathResults[0].Client)
	}
	if receivedBody.ScanUserInfo.Hostname == "" {
		t.Error("expected non-empty hostname")
	}
	if receivedBody.ScanUserInfo.Username == "" {
		t.Error("expected non-empty username")
	}
}

func TestUpload_EmptyResults(t *testing.T) {
	var requestMade atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMade.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	u := NewUploader()
	server := models.ControlServer{URL: ts.URL}

	err := u.Upload(context.Background(), nil, server)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if requestMade.Load() {
		t.Error("expected no HTTP request for empty results")
	}

	err = u.Upload(context.Background(), []models.ScanPathResult{}, server)
	if err != nil {
		t.Fatalf("expected nil error for empty slice, got %v", err)
	}
	if requestMade.Load() {
		t.Error("expected no HTTP request for empty slice")
	}
}

func TestUpload_4xxNoRetry(t *testing.T) {
	var requestCount atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer ts.Close()

	u := NewUploader()
	results := []models.ScanPathResult{
		{Client: "test", Path: "/p"},
	}
	server := models.ControlServer{URL: ts.URL}

	err := u.Upload(context.Background(), results, server)
	if err == nil {
		t.Fatal("expected error for 400 response")
	}

	count := requestCount.Load()
	if count != 1 {
		t.Errorf("expected exactly 1 request (no retry on 4xx), got %d", count)
	}

	// Verify it's a ClientError
	var ce *httperrors.ClientError
	if !errors.As(err, &ce) {
		t.Errorf("expected ClientError in chain, got %T: %v", err, err)
	}
}

func TestUpload_5xxRetries(t *testing.T) {
	var requestCount atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}))
	defer ts.Close()

	u := NewUploader()
	results := []models.ScanPathResult{
		{Client: "test", Path: "/p"},
	}
	server := models.ControlServer{URL: ts.URL}

	// Use a context with a bounded deadline to avoid waiting for full backoff
	// while still allowing multiple retries. The first request is immediate,
	// then backoff is 1s, 2s, so we give ample time for at least two attempts.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := u.Upload(ctx, results, server)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}

	count := requestCount.Load()
	if count < 2 {
		t.Errorf("expected at least 2 requests (retries on 5xx), got %d", count)
	}
}

func TestUpload_CustomHeaders(t *testing.T) {
	var receivedHeaders http.Header

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	u := NewUploader()
	results := []models.ScanPathResult{
		{Client: "test", Path: "/p"},
	}
	server := models.ControlServer{
		URL: ts.URL,
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
			"X-Custom":      "custom-value",
		},
	}

	err := u.Upload(context.Background(), results, server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedHeaders.Get("Authorization") != "Bearer test-token" {
		t.Errorf(
			"expected Authorization header 'Bearer test-token', got %q",
			receivedHeaders.Get("Authorization"),
		)
	}
	if receivedHeaders.Get("X-Custom") != "custom-value" {
		t.Errorf("expected X-Custom header 'custom-value', got %q", receivedHeaders.Get("X-Custom"))
	}
}

func TestUpload_ScanMetadataVersionPopulated(t *testing.T) {
	var receivedBody models.ScanPathResultsCreate

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&receivedBody); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	u := NewUploader()
	results := []models.ScanPathResult{
		{Client: "test", Path: "/p"},
	}
	server := models.ControlServer{URL: ts.URL}

	err := u.Upload(context.Background(), results, server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedBody.ScanMetadata == nil {
		t.Fatal("expected ScanMetadata to be non-nil")
	}
	if receivedBody.ScanMetadata.Version == "" {
		t.Error("expected ScanMetadata.Version to be populated")
	}
}

func TestUpload_ContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow server; sleep just long enough to exceed the client context deadline
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	u := NewUploader()
	results := []models.ScanPathResult{
		{Client: "test", Path: "/p"},
	}
	server := models.ControlServer{URL: ts.URL}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := u.Upload(ctx, results, server)
	if err == nil {
		t.Fatal("expected error due to context cancellation")
	}
}
