package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/user"
	"time"

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

	// Redact sensitive data before upload
	redacted := make([]models.ScanPathResult, len(results))
	copy(redacted, results)
	for i := range redacted {
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
				"upload failed due to non-retryable client error after %d attempt(s) (url=%s, status=%d): %w",
				attempt+1,
				server.URL,
				ce.StatusCode,
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
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode < 500 {
			return &clientError{StatusCode: resp.StatusCode, Body: string(respBody)}
		}
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
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
