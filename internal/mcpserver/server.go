package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/go-authgate/agent-scanner/internal/models"
	"github.com/go-authgate/agent-scanner/internal/version"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ScanFunc is a function that runs the scanner pipeline and returns results.
type ScanFunc func(ctx context.Context, paths []string, skills bool) ([]models.ScanPathResult, error)

// ServerConfig holds the configuration for the MCP server.
type ServerConfig struct {
	ScanFn       ScanFunc
	Background   bool
	ScanInterval time.Duration
	ClientName   string
}

// ScanState holds the cached scan results and provides thread-safe access.
type ScanState struct {
	mu      sync.RWMutex
	results []models.ScanPathResult
}

// Set stores scan results in the cache.
func (s *ScanState) Set(results []models.ScanPathResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = results
}

// Get retrieves the cached scan results.
func (s *ScanState) Get() []models.ScanPathResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.results
}

// scanInput is the typed input for the scan tool.
type scanInput struct {
	Paths  []string `json:"paths,omitempty"  jsonschema:"optional list of config file paths or directories to scan"`
	Skills bool     `json:"skills,omitempty" jsonschema:"whether to include skill scanning"`
}

// scanOutput is the typed output from the scan tool.
type scanOutput struct {
	Results []models.ScanPathResult `json:"results"`
	Summary scanSummary             `json:"summary"`
}

// scanSummary provides a high-level overview of scan results.
type scanSummary struct {
	TotalPaths   int `json:"total_paths"`
	TotalServers int `json:"total_servers"`
	TotalIssues  int `json:"total_issues"`
	Critical     int `json:"critical"`
	High         int `json:"high"`
	Medium       int `json:"medium"`
	Low          int `json:"low"`
	Info         int `json:"info"`
}

// getResultsInput is the typed input for the get_scan_results tool (empty).
type getResultsInput struct{}

// getResultsOutput is the typed output from the get_scan_results tool.
type getResultsOutput struct {
	Results []models.ScanPathResult `json:"results"`
	Summary scanSummary             `json:"summary"`
}

// buildSummary creates a summary from scan results.
func buildSummary(results []models.ScanPathResult) scanSummary {
	summary := scanSummary{
		TotalPaths: len(results),
	}
	for _, r := range results {
		summary.TotalServers += len(r.Servers)
		for _, issue := range r.Issues {
			summary.TotalIssues++
			switch issue.GetSeverity() {
			case models.SeverityCritical:
				summary.Critical++
			case models.SeverityHigh:
				summary.High++
			case models.SeverityMedium:
				summary.Medium++
			case models.SeverityLow:
				summary.Low++
			case models.SeverityInfo:
				summary.Info++
			}
		}
	}
	return summary
}

// NewServer creates a configured MCP server with scan and get_scan_results tools.
// It returns the server and the scan state used for caching results.
func NewServer(cfg ServerConfig) (*mcp.Server, *ScanState) {
	state := &ScanState{}

	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "agent-scanner",
			Version: version.Version,
		},
		&mcp.ServerOptions{
			Instructions: "Agent Scanner is a security scanner for AI agents, MCP servers, and agent skills. " +
				"Use the 'scan' tool to discover and analyze MCP servers for security threats. " +
				"Use the 'get_scan_results' tool to retrieve the results of the last scan.",
		},
	)

	// Register scan tool
	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan",
		Description: "Scan MCP servers and agent skills for security issues. Discovers installed AI agent clients, connects to their configured MCP servers, and detects prompt injections, tool poisoning, toxic flows, and other security threats.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input scanInput) (*mcp.CallToolResult, scanOutput, error) {
		if cfg.ScanFn == nil {
			return nil, scanOutput{}, errors.New("scan function not configured")
		}

		results, err := cfg.ScanFn(ctx, input.Paths, input.Skills)
		if err != nil {
			return nil, scanOutput{}, fmt.Errorf("scan failed: %w", err)
		}

		// Cache the results
		state.Set(results)

		output := scanOutput{
			Results: results,
			Summary: buildSummary(results),
		}

		// Also provide a text summary in the content for easy consumption
		jsonBytes, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return nil, output, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: string(jsonBytes)},
			},
		}, output, nil
	})

	// Register get_scan_results tool
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_scan_results",
		Description: "Get the results of the last security scan. Returns cached results from the most recent scan, or empty results if no scan has been performed yet.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ getResultsInput) (*mcp.CallToolResult, getResultsOutput, error) {
		results := state.Get()
		if results == nil {
			results = []models.ScanPathResult{}
		}

		output := getResultsOutput{
			Results: results,
			Summary: buildSummary(results),
		}

		jsonBytes, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return nil, output, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: string(jsonBytes)},
			},
		}, output, nil
	})

	return server, state
}

// RunServer creates and runs the MCP server over stdio.
func RunServer(cfg ServerConfig) error {
	server, state := NewServer(cfg)

	ctx := context.Background()

	// If background scanning is enabled, run initial scan and start periodic scanning
	if cfg.Background && cfg.ScanFn != nil {
		interval := cfg.ScanInterval
		if interval == 0 {
			interval = 30 * time.Minute
		}

		// Run initial scan
		go func() {
			slog.Info("running initial background scan")
			results, err := cfg.ScanFn(ctx, nil, false)
			if err != nil {
				slog.Error("initial background scan failed", "error", err)
				return
			}
			state.Set(results)
			slog.Info("initial background scan complete",
				"paths", len(results),
			)
		}()

		// Start periodic scanning
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					slog.Info("running periodic background scan")
					results, err := cfg.ScanFn(ctx, nil, false)
					if err != nil {
						slog.Error("periodic background scan failed", "error", err)
						continue
					}
					state.Set(results)
					slog.Info("periodic background scan complete",
						"paths", len(results),
					)
				}
			}
		}()
	}

	slog.Info("starting MCP server", "name", "agent-scanner", "version", version.Version)
	return server.Run(ctx, &mcp.StdioTransport{})
}
