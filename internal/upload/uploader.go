package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"os/user"
	"strings"
	"time"
	"unicode"

	"github.com/go-authgate/agent-scanner/internal/models"
	"github.com/go-authgate/agent-scanner/internal/redact"
	"github.com/go-authgate/agent-scanner/internal/version"
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
// (e.g., request construction failures).
type nonRetryableError struct {
	err error
}

func (e *nonRetryableError) Error() string { return e.err.Error() }
func (e *nonRetryableError) Unwrap() error { return e.err }

// Uploader pushes scan results to control servers.
type Uploader interface {
	Upload(ctx context.Context, results []models.ScanPathResult, server models.ControlServer) error
}

type uploader struct {
	httpClient *http.Client
}

// NewUploader creates a new Uploader.
func NewUploader() Uploader {
	return &uploader{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (u *uploader) Upload(
	ctx context.Context,
	results []models.ScanPathResult,
	server models.ControlServer,
) error {
	if len(results) == 0 {
		return nil
	}

	// Deep-clone results before redaction to avoid mutating the caller's data.
	// redact.ScanPathResult modifies Server configs (Env, Headers, Args) in place,
	// so we must clone the server pointers, not just the slice.
	redacted := make([]models.ScanPathResult, len(results))
	copy(redacted, results)
	for i := range redacted {
		if redacted[i].Error != nil {
			errCopy := *redacted[i].Error
			redacted[i].Error = &errCopy
		}
		if len(redacted[i].Servers) > 0 {
			servers := make([]models.ServerScanResult, len(redacted[i].Servers))
			copy(servers, redacted[i].Servers)
			for j := range servers {
				servers[j].Server = cloneServerConfig(servers[j].Server)
				if servers[j].Error != nil {
					errCopy := *servers[j].Error
					servers[j].Error = &errCopy
				}
			}
			redacted[i].Servers = servers
		}
		redact.ScanPathResult(&redacted[i])
	}

	payload := models.ScanPathResultsCreate{
		ScanPathResults: redacted,
		ScanUserInfo: models.ScanUserInfo{
			Hostname: getHostname(),
			Username: getUsername(),
		},
		ScanMetadata: &models.ScanMetadata{
			Version: version.Version,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal upload payload: %w", err)
	}

	// Retry with exponential backoff (only retry on 5xx / network errors)
	maxRetries := 3
	for attempt := range maxRetries {
		err = u.doUpload(ctx, server, body)
		if err == nil {
			slog.Info("upload successful", "url", server.URL)
			return nil
		}
		// Do not retry client errors (4xx) or non-retryable errors (e.g., bad URL)
		var nre *nonRetryableError
		if errors.As(err, &nre) {
			return fmt.Errorf("upload failed: %w", err)
		}
		var ce *clientError
		if errors.As(err, &ce) {
			return fmt.Errorf(
				"upload failed due to non-retryable client error after %d attempt(s): %w",
				attempt+1,
				err,
			)
		}
		if attempt < maxRetries-1 {
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			slog.Debug("retrying upload", "attempt", attempt+1, "backoff", backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return fmt.Errorf("upload failed after %d attempts: %w", maxRetries, err)
}

func (u *uploader) doUpload(ctx context.Context, server models.ControlServer, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, bytes.NewReader(body))
	if err != nil {
		return &nonRetryableError{err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range server.Headers {
		req.Header.Set(k, v)
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		bodySnippet := sanitizeBodySnippet(string(respBody), 512)
		if resp.StatusCode < 500 {
			return &clientError{StatusCode: resp.StatusCode, Body: bodySnippet}
		}
		return fmt.Errorf("status %d: %s", resp.StatusCode, bodySnippet)
	}

	// Drain response body on success to allow HTTP connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)

	return nil
}

// cloneServerConfig returns a deep copy of a ServerConfig to avoid
// mutating the original during redaction.
func cloneServerConfig(cfg models.ServerConfig) models.ServerConfig {
	switch s := cfg.(type) {
	case *models.StdioServer:
		c := *s
		if s.Env != nil {
			c.Env = make(map[string]string, len(s.Env))
			maps.Copy(c.Env, s.Env)
		}
		if s.Args != nil {
			c.Args = make([]string, len(s.Args))
			copy(c.Args, s.Args)
		}
		return &c
	case *models.RemoteServer:
		c := *s
		if s.Headers != nil {
			c.Headers = make(map[string]string, len(s.Headers))
			maps.Copy(c.Headers, s.Headers)
		}
		return &c
	default:
		return cfg
	}
}

func getHostname() string {
	if h := os.Getenv("AGENT_SCAN_CI_HOSTNAME"); h != "" {
		return h
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func getUsername() string {
	u, err := user.Current()
	if err != nil {
		return "unknown"
	}
	return u.Username
}

// sanitizeBodySnippet truncates s to approximately maxLen bytes (the
// returned string may be slightly longer due to a " [truncated]" suffix)
// and replaces all Unicode control characters with spaces for safe single-line logging.
func sanitizeBodySnippet(s string, maxLen int) string {
	if len(s) > maxLen {
		s = s[:maxLen] + " [truncated]"
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}
