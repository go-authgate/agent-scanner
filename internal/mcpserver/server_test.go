package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-authgate/agent-scanner/internal/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mockScanResults returns test scan results.
func mockScanResults() []models.ScanPathResult {
	return []models.ScanPathResult{
		{
			Client: "test-client",
			Path:   "/tmp/test-config.json",
			Servers: []models.ServerScanResult{
				{
					Name: "test-server",
					Server: &models.StdioServer{
						Command: "test-cmd",
						Args:    []string{"--flag"},
					},
					Signature: &models.ServerSignature{
						Metadata: models.InitializeResult{
							ServerInfo: models.ServerInfo{
								Name:    "test-server",
								Version: "1.0.0",
							},
						},
						Tools: []models.Tool{
							{Name: "test-tool", Description: "A test tool"},
						},
					},
				},
			},
			Issues: []models.Issue{
				{
					Code:    models.CodeSuspiciousWords,
					Message: "Found suspicious words in tool description",
				},
				{
					Code:    models.CodePromptInjection,
					Message: "Prompt injection detected",
				},
			},
		},
	}
}

func TestNewServer_RegistersTools(t *testing.T) {
	cfg := ServerConfig{
		ScanFn: func(_ context.Context, _ []string, _ bool) ([]models.ScanPathResult, error) {
			return nil, nil
		},
	}

	server, _ := NewServer(cfg)

	// Connect a test client to verify tools are registered
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v1.0.0"}, nil)

	t1, t2 := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, t1, nil); err != nil {
		t.Fatalf("server.Connect failed: %v", err)
	}
	session, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client.Connect failed: %v", err)
	}
	defer session.Close()

	// List tools
	toolsResult, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	toolNames := make(map[string]bool)
	for _, tool := range toolsResult.Tools {
		toolNames[tool.Name] = true
	}

	if !toolNames["scan"] {
		t.Error("expected 'scan' tool to be registered")
	}
	if !toolNames["get_scan_results"] {
		t.Error("expected 'get_scan_results' tool to be registered")
	}
	if len(toolsResult.Tools) != 2 {
		t.Errorf("expected 2 tools, got %d", len(toolsResult.Tools))
	}
}

func TestScanTool_CallsScanFunc(t *testing.T) {
	var scanCalled atomic.Bool
	expectedResults := mockScanResults()

	cfg := ServerConfig{
		ScanFn: func(_ context.Context, paths []string, skills bool) ([]models.ScanPathResult, error) {
			scanCalled.Store(true)
			if len(paths) != 1 || paths[0] != "/tmp/config.json" {
				t.Errorf("unexpected paths: %v", paths)
			}
			if !skills {
				t.Error("expected skills=true")
			}
			return expectedResults, nil
		},
	}

	server, _ := NewServer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v1.0.0"}, nil)

	t1, t2 := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, t1, nil); err != nil {
		t.Fatalf("server.Connect failed: %v", err)
	}
	session, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client.Connect failed: %v", err)
	}
	defer session.Close()

	// Call the scan tool
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "scan",
		Arguments: map[string]any{
			"paths":  []string{"/tmp/config.json"},
			"skills": true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool scan failed: %v", err)
	}

	if !scanCalled.Load() {
		t.Error("scan function was not called")
	}

	if result.IsError {
		t.Error("expected no error in result")
	}

	// Verify the structured content has the expected JSON
	if len(result.Content) == 0 {
		t.Fatal("expected content in result")
	}

	// Parse the text content to verify structure
	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}

	// Parse into a generic map since ServerConfig is an interface
	var output map[string]any
	if err := json.Unmarshal([]byte(textContent.Text), &output); err != nil {
		t.Fatalf("failed to parse scan output: %v", err)
	}

	results, ok := output["results"].([]any)
	if !ok {
		t.Fatal("expected results array in output")
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}

	summary, ok := output["summary"].(map[string]any)
	if !ok {
		t.Fatal("expected summary in output")
	}
	if totalIssues := summary["total_issues"].(float64); totalIssues != 2 {
		t.Errorf("expected 2 total issues, got %v", totalIssues)
	}
	if totalServers := summary["total_servers"].(float64); totalServers != 1 {
		t.Errorf("expected 1 total server, got %v", totalServers)
	}
}

func TestGetScanResults_EmptyInitially(t *testing.T) {
	cfg := ServerConfig{
		ScanFn: func(_ context.Context, _ []string, _ bool) ([]models.ScanPathResult, error) {
			return nil, nil
		},
	}

	server, _ := NewServer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v1.0.0"}, nil)

	t1, t2 := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, t1, nil); err != nil {
		t.Fatalf("server.Connect failed: %v", err)
	}
	session, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client.Connect failed: %v", err)
	}
	defer session.Close()

	// Call get_scan_results before any scan
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_scan_results",
	})
	if err != nil {
		t.Fatalf("CallTool get_scan_results failed: %v", err)
	}

	if result.IsError {
		t.Error("expected no error in result")
	}

	// Parse the content
	if len(result.Content) == 0 {
		t.Fatal("expected content in result")
	}

	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}

	var output getResultsOutput
	if err := json.Unmarshal([]byte(textContent.Text), &output); err != nil {
		t.Fatalf("failed to parse output: %v", err)
	}

	if len(output.Results) != 0 {
		t.Errorf("expected 0 results initially, got %d", len(output.Results))
	}
	if output.Summary.TotalIssues != 0 {
		t.Errorf("expected 0 issues initially, got %d", output.Summary.TotalIssues)
	}
}

func TestGetScanResults_ReturnsCachedResults(t *testing.T) {
	expectedResults := mockScanResults()

	cfg := ServerConfig{
		ScanFn: func(_ context.Context, _ []string, _ bool) ([]models.ScanPathResult, error) {
			return expectedResults, nil
		},
	}

	server, _ := NewServer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v1.0.0"}, nil)

	t1, t2 := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, t1, nil); err != nil {
		t.Fatalf("server.Connect failed: %v", err)
	}
	session, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client.Connect failed: %v", err)
	}
	defer session.Close()

	// First, run a scan to populate the cache
	_, err = session.CallTool(ctx, &mcp.CallToolParams{
		Name: "scan",
	})
	if err != nil {
		t.Fatalf("CallTool scan failed: %v", err)
	}

	// Now get cached results
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_scan_results",
	})
	if err != nil {
		t.Fatalf("CallTool get_scan_results failed: %v", err)
	}

	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}

	var output map[string]any
	if err := json.Unmarshal([]byte(textContent.Text), &output); err != nil {
		t.Fatalf("failed to parse output: %v", err)
	}

	results, ok := output["results"].([]any)
	if !ok {
		t.Fatal("expected results array in output")
	}
	if len(results) != 1 {
		t.Errorf("expected 1 cached result, got %d", len(results))
	}

	firstResult, ok := results[0].(map[string]any)
	if !ok {
		t.Fatal("expected first result to be an object")
	}
	if firstResult["client"] != "test-client" {
		t.Errorf("expected client 'test-client', got %v", firstResult["client"])
	}

	summary, ok := output["summary"].(map[string]any)
	if !ok {
		t.Fatal("expected summary in output")
	}
	if totalIssues := summary["total_issues"].(float64); totalIssues != 2 {
		t.Errorf("expected 2 issues in cached results, got %v", totalIssues)
	}
}

func TestBuildSummary(t *testing.T) {
	results := []models.ScanPathResult{
		{
			Servers: []models.ServerScanResult{
				{Name: "server-1"},
				{Name: "server-2"},
			},
			Issues: []models.Issue{
				{
					Code:    models.CodePromptInjection,
					Message: "injection",
				}, // high
				{
					Code:    models.CodeBehaviorHijack,
					Message: "hijack",
				}, // critical
				{
					Code:    models.CodeSuspiciousWords,
					Message: "suspicious",
				}, // medium
				{
					Code:    models.CodeDataLeakFlow,
					Message: "leak",
				}, // high (TF)
				{
					Code:      models.CodeServerStartup,
					Message:   "startup",
					ExtraData: map[string]any{"severity": "info"},
				}, // info (custom)
			},
		},
		{
			Servers: []models.ServerScanResult{
				{Name: "server-3"},
			},
			Issues: []models.Issue{
				{Code: models.CodeSkillInjection, Message: "skill injection"}, // critical
			},
		},
	}

	summary := buildSummary(results)

	if summary.TotalPaths != 2 {
		t.Errorf("expected 2 paths, got %d", summary.TotalPaths)
	}
	if summary.TotalServers != 3 {
		t.Errorf("expected 3 servers, got %d", summary.TotalServers)
	}
	if summary.TotalIssues != 6 {
		t.Errorf("expected 6 issues, got %d", summary.TotalIssues)
	}
	if summary.Critical != 2 {
		t.Errorf("expected 2 critical, got %d", summary.Critical)
	}
	if summary.High != 2 {
		t.Errorf("expected 2 high, got %d", summary.High)
	}
	if summary.Medium != 1 {
		t.Errorf("expected 1 medium, got %d", summary.Medium)
	}
	if summary.Info != 1 {
		t.Errorf("expected 1 info, got %d", summary.Info)
	}
}

func TestScanState_Concurrency(t *testing.T) {
	state := &ScanState{}

	// Verify initial state
	got := state.Get()
	if got != nil {
		t.Errorf("expected nil initially, got %v", got)
	}

	// Set results
	expected := mockScanResults()
	state.Set(expected)

	// Verify retrieval
	got = state.Get()
	if len(got) != len(expected) {
		t.Errorf("expected %d results, got %d", len(expected), len(got))
	}

	// Overwrite with empty
	state.Set([]models.ScanPathResult{})
	got = state.Get()
	if len(got) != 0 {
		t.Errorf("expected 0 results after overwrite, got %d", len(got))
	}

	// Exercise concurrent Set/Get to verify thread safety under -race.
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			state.Set([]models.ScanPathResult{
				{Client: fmt.Sprintf("client-%d", n), Path: "/p"},
			})
		}(i)
		go func() {
			defer wg.Done()
			_ = state.Get()
		}()
	}
	wg.Wait()
}
