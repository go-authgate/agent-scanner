package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/user"
	"time"

	"github.com/go-authgate/agent-scanner/internal/models"
	"github.com/go-authgate/agent-scanner/internal/redact"
)

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
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal upload payload: %w", err)
	}

	// Retry with exponential backoff
	maxRetries := 3
	for attempt := range maxRetries {
		err = u.doUpload(ctx, server, body)
		if err == nil {
			slog.Info("upload successful", "url", server.URL)
			return nil
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
		return err
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
