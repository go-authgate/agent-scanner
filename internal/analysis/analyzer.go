package analysis

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-authgate/agent-scanner/internal/models"
)

// Analyzer performs security analysis on scan results.
type Analyzer interface {
	Analyze(ctx context.Context, results []models.ScanPathResult) ([]models.ScanPathResult, error)
}

type remoteAnalyzer struct {
	analysisURL string
	httpClient  *http.Client
}

// NewAnalyzer creates a new remote analyzer.
func NewAnalyzer(analysisURL string, skipSSLVerify bool) Analyzer {
	t := http.DefaultTransport.(*http.Transport).Clone()
	if skipSSLVerify {
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
	return &remoteAnalyzer{
		analysisURL: analysisURL,
		httpClient:  &http.Client{Timeout: 60 * time.Second, Transport: t},
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

	// Retry with exponential backoff
	var resp analysisResponse
	maxRetries := 3
	for attempt := range maxRetries {
		err = a.doRequest(ctx, body, &resp)
		if err == nil {
			break
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
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	httpResp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(httpResp.Body)
		return fmt.Errorf("status %d: %s", httpResp.StatusCode, string(respBody))
	}

	return json.NewDecoder(httpResp.Body).Decode(resp)
}
