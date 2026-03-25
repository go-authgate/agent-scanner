package analysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-authgate/agent-scanner/internal/models"
	"github.com/go-authgate/agent-scanner/internal/tlsutil"
)

// clientError is a non-retryable HTTP error (4xx).
type clientError struct {
	StatusCode int
	Body       string
}

func (e *clientError) Error() string {
	return fmt.Sprintf("status %d: %s", e.StatusCode, e.Body)
}

// nonRetryableError wraps errors that should not be retried
// (e.g., request construction failures, JSON decode errors).
type nonRetryableError struct {
	err error
}

func (e *nonRetryableError) Error() string { return e.err.Error() }
func (e *nonRetryableError) Unwrap() error { return e.err }

// Analyzer performs security analysis on scan results.
type Analyzer interface {
	Analyze(ctx context.Context, results []models.ScanPathResult) ([]models.ScanPathResult, error)
}

type remoteAnalyzer struct {
	analysisURL string
	httpClient  *http.Client
}

// newAnalyzerTransport returns an http.RoundTripper with TLS verification
// disabled when skipSSLVerify is true, and nil (shared default) otherwise.
func newAnalyzerTransport(skipSSLVerify bool) http.RoundTripper {
	if !skipSSLVerify {
		return nil
	}
	t := tlsutil.CloneTransport()
	tlsutil.ApplyInsecureSkipVerify(t)
	return t
}

// NewAnalyzer creates a new remote analyzer.
func NewAnalyzer(analysisURL string, skipSSLVerify bool) Analyzer {
	return &remoteAnalyzer{
		analysisURL: analysisURL,
		httpClient: &http.Client{
			Timeout:   60 * time.Second,
			Transport: newAnalyzerTransport(skipSSLVerify),
		},
	}
}

// analysisRequest is the payload sent to the analysis API.
type analysisRequest struct {
	Servers []analysisServer `json:"servers"`
}

type analysisServer struct {
	Name  string        `json:"name"`
	Tools []models.Tool `json:"tools"`
}

// analysisResponse is the response from the analysis API.
type analysisResponse struct {
	Issues []models.Issue              `json:"issues"`
	Labels [][]models.ScalarToolLabels `json:"labels"`
}

func (a *remoteAnalyzer) Analyze(
	ctx context.Context,
	results []models.ScanPathResult,
) ([]models.ScanPathResult, error) {
	if a.analysisURL == "" {
		slog.Debug("no analysis URL configured, skipping remote analysis")
		return results, nil
	}

	for i := range results {
		result := &results[i]
		if err := a.analyzePathResult(ctx, result); err != nil {
			slog.Warn("remote analysis failed", "path", result.Path, "error", err)
			// Don't fail the whole scan; continue with local checks only
		}
	}

	return results, nil
}

func (a *remoteAnalyzer) analyzePathResult(
	ctx context.Context,
	result *models.ScanPathResult,
) error {
	// Build analysis request from verified servers
	var servers []analysisServer
	for _, server := range result.Servers {
		if server.Signature == nil {
			continue
		}
		// Convert all entities to Tool format for uniform analysis
		var tools []models.Tool
		for _, entity := range server.Signature.Entities() {
			tools = append(tools, models.EntityToTool(entity))
		}
		servers = append(servers, analysisServer{
			Name:  server.Name,
			Tools: tools,
		})
	}

	if len(servers) == 0 {
		return nil
	}

	reqBody := analysisRequest{Servers: servers}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	// Retry with exponential backoff (only retry on 5xx / network errors)
	var resp analysisResponse
	maxRetries := 3
	for attempt := range maxRetries {
		err = a.doRequest(ctx, body, &resp)
		if err == nil {
			break
		}
		// Do not retry non-retryable errors (bad URL, JSON decode, etc.)
		var nre *nonRetryableError
		if errors.As(err, &nre) {
			return fmt.Errorf("analysis API: %w", err)
		}
		// Do not retry client errors (4xx)
		var ce *clientError
		if errors.As(err, &ce) {
			return fmt.Errorf("analysis API: %w", err)
		}
		if attempt < maxRetries-1 {
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			slog.Debug("retrying analysis", "attempt", attempt+1, "backoff", backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if err != nil {
		return fmt.Errorf("analysis API: %w", err)
	}

	// Merge results
	result.Issues = append(result.Issues, resp.Issues...)
	result.Labels = resp.Labels

	return nil
}

func (a *remoteAnalyzer) doRequest(ctx context.Context, body []byte, resp *analysisResponse) error {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		a.analysisURL,
		bytes.NewReader(body),
	)
	if err != nil {
		return &nonRetryableError{err: err}
	}
	req.Header.Set("Content-Type", "application/json")

	httpResp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 4096))
		bodySnippet := sanitizeBodySnippet(string(respBody), 512)
		if httpResp.StatusCode < 500 {
			return &clientError{StatusCode: httpResp.StatusCode, Body: bodySnippet}
		}
		return fmt.Errorf("status %d: %s", httpResp.StatusCode, bodySnippet)
	}

	if err := json.NewDecoder(httpResp.Body).Decode(resp); err != nil {
		return &nonRetryableError{err: fmt.Errorf("decode response: %w", err)}
	}
	return nil
}

// sanitizeBodySnippet truncates s to maxLen bytes and replaces
// newlines/control characters with spaces for safe single-line logging.
func sanitizeBodySnippet(s string, maxLen int) string {
	if len(s) > maxLen {
		s = s[:maxLen] + " [truncated]"
	}
	replacer := strings.NewReplacer("\r\n", " ", "\r", " ", "\n", " ", "\t", " ")
	return replacer.Replace(s)
}
