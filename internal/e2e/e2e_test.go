package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-authgate/agent-scanner/internal/discovery"
	"github.com/go-authgate/agent-scanner/internal/inspect"
	"github.com/go-authgate/agent-scanner/internal/mcpclient"
	"github.com/go-authgate/agent-scanner/internal/models"
	"github.com/go-authgate/agent-scanner/internal/output"
	"github.com/go-authgate/agent-scanner/internal/pipeline"
	"github.com/go-authgate/agent-scanner/internal/rules"
)

var (
	mathServerBin    string
	weatherServerBin string
)

func TestMain(m *testing.M) {
	code := setupAndRun(m)
	os.Exit(code)
}

func setupAndRun(m *testing.M) int {
	// E2E tests build external binaries and are slow; skip under -short.
	if testing.Short() {
		fmt.Fprintln(os.Stderr, "skipping E2E tests in short mode")
		return 0
	}

	tmpDir, err := os.MkdirTemp("", "e2e-testservers-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		return 1
	}
	defer os.RemoveAll(tmpDir)

	exeSuffix := ""
	if runtime.GOOS == "windows" {
		exeSuffix = ".exe"
	}
	mathServerBin = filepath.Join(tmpDir, "math-server"+exeSuffix)
	weatherServerBin = filepath.Join(tmpDir, "weather-server"+exeSuffix)

	// Build test server binaries.
	for _, b := range []struct {
		pkg  string
		dest string
	}{
		{"./cmd/testserver-math", mathServerBin},
		{"./cmd/testserver-weather", weatherServerBin},
	} {
		cmd := exec.Command("go", "build", "-o", b.dest, b.pkg)
		cmd.Dir = repoRoot()
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(
				os.Stderr, "failed to build %s: %v\n", b.pkg, err,
			)
			return 1
		}
	}

	return m.Run()
}

// repoRoot returns the absolute path to the repository root.
func repoRoot() string {
	// Walk up from current file's directory to find go.mod.
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("could not find repo root (go.mod)")
		}
		dir = parent
	}
}

// writeConfig writes a temporary Claude-format MCP config file
// pointing to the given server binary.
func writeConfig(t *testing.T, serverName, binaryPath string) string {
	t.Helper()
	cfg := map[string]any{
		"mcpServers": map[string]any{
			serverName: map[string]any{
				"command": binaryPath,
				"args":    []string{},
			},
		},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "claude_desktop_config.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// runPipeline executes the full scan pipeline for the given config path.
func runPipeline(
	t *testing.T,
	configPath string,
	inspectOnly bool,
) []models.ScanPathResult {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	disc := discovery.NewDiscoverer()
	mcpClient := mcpclient.NewClient(false)
	insp := inspect.NewInspector(mcpClient, 15)

	cfg := pipeline.Config{
		Discoverer:  disc,
		Inspector:   insp,
		RuleEngine:  rules.NewDefaultEngine(),
		Paths:       []string{configPath},
		InspectOnly: inspectOnly,
	}

	p := pipeline.New(cfg)
	results, err := p.Run(ctx)
	if err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}
	return results
}

func TestE2E_ScanMathServer(t *testing.T) {
	configPath := writeConfig(t, "math", mathServerBin)
	results := runPipeline(t, configPath, false)

	// 1 scan path result.
	if len(results) != 1 {
		t.Fatalf("expected 1 scan path result, got %d", len(results))
	}
	r := results[0]

	// 1 server named "math".
	if len(r.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(r.Servers))
	}
	srv := r.Servers[0]
	if srv.Name != "math" {
		t.Errorf("expected server name 'math', got %q", srv.Name)
	}
	if srv.Error != nil {
		t.Fatalf("unexpected server error: %s", srv.Error.Message)
	}

	// Server has a valid signature with 2 tools.
	if srv.Signature == nil {
		t.Fatal("expected non-nil signature")
	}
	if len(srv.Signature.Tools) != 2 {
		t.Errorf("expected 2 tools, got %d", len(srv.Signature.Tools))
	}

	// Verify tool names.
	toolNames := make(map[string]bool)
	for _, tool := range srv.Signature.Tools {
		toolNames[tool.Name] = true
	}
	for _, name := range []string{"add", "multiply"} {
		if !toolNames[name] {
			t.Errorf("expected tool %q not found", name)
		}
	}

	// No issues detected (clean server).
	if len(r.Issues) != 0 {
		t.Errorf("expected 0 issues, got %d", len(r.Issues))
		for _, issue := range r.Issues {
			t.Logf("  issue: [%s] %s", issue.Code, issue.Message)
		}
	}
}

func TestE2E_ScanWeatherServer(t *testing.T) {
	configPath := writeConfig(t, "weather", weatherServerBin)
	results := runPipeline(t, configPath, false)

	if len(results) != 1 {
		t.Fatalf("expected 1 scan path result, got %d", len(results))
	}
	r := results[0]

	if len(r.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(r.Servers))
	}
	srv := r.Servers[0]
	if srv.Error != nil {
		t.Fatalf("unexpected server error: %s", srv.Error.Message)
	}
	if srv.Signature == nil {
		t.Fatal("expected non-nil signature")
	}
	if len(srv.Signature.Tools) != 2 {
		t.Errorf("expected 2 tools, got %d", len(srv.Signature.Tools))
	}

	// Should detect security issues.
	if len(r.Issues) == 0 {
		t.Fatal("expected at least one issue, got 0")
	}

	// Collect issue codes.
	codes := make(map[string]bool)
	for _, issue := range r.Issues {
		codes[issue.Code] = true
	}

	// W001: suspicious trigger words ("ignore all previous", "<important>", etc.)
	if !codes[models.CodeSuspiciousWords] {
		t.Errorf("expected W001 (suspicious trigger words) issue")
	}
	// E005: suspicious URLs (bit.ly)
	if !codes[models.CodeSuspiciousURL] {
		t.Errorf("expected E005 (suspicious URLs) issue")
	}

	t.Logf("detected %d issue(s):", len(r.Issues))
	for _, issue := range r.Issues {
		t.Logf("  [%s] %s", issue.Code, issue.Message)
	}
}

func TestE2E_InspectOnly(t *testing.T) {
	configPath := writeConfig(t, "math", mathServerBin)
	results := runPipeline(t, configPath, true)

	if len(results) != 1 {
		t.Fatalf("expected 1 scan path result, got %d", len(results))
	}
	r := results[0]

	// Server signatures should still be present.
	if len(r.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(r.Servers))
	}
	if r.Servers[0].Signature == nil {
		t.Fatal("expected non-nil signature in inspect-only mode")
	}
	if len(r.Servers[0].Signature.Tools) != 2 {
		t.Errorf("expected 2 tools, got %d", len(r.Servers[0].Signature.Tools))
	}

	// No issues in inspect-only mode (rules not run).
	if len(r.Issues) != 0 {
		t.Errorf("expected 0 issues in inspect-only mode, got %d", len(r.Issues))
	}
}

func TestE2E_JSONOutput(t *testing.T) {
	configPath := writeConfig(t, "math", mathServerBin)
	results := runPipeline(t, configPath, false)

	var buf bytes.Buffer
	formatter := output.NewJSONFormatter(&buf)
	if err := formatter.FormatResults(results, output.FormatOptions{}); err != nil {
		t.Fatalf("JSON format error: %v", err)
	}

	// Verify valid JSON.
	var decoded []json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON output: %v\noutput: %s", err, buf.String())
	}
	if len(decoded) != 1 {
		t.Errorf("expected 1 result in JSON output, got %d", len(decoded))
	}

	// Re-decode into generic maps to verify structure without interface issues.
	var scanResults []map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &scanResults); err != nil {
		t.Fatalf("unmarshal scan results: %v", err)
	}
	if len(scanResults) != 1 {
		t.Fatalf("expected 1 scan result, got %d", len(scanResults))
	}
	serversRaw, ok := scanResults[0]["servers"]
	if !ok {
		t.Fatal("expected 'servers' key in JSON output")
	}
	var servers []map[string]any
	if err := json.Unmarshal(serversRaw, &servers); err != nil {
		t.Fatalf("unmarshal servers: %v", err)
	}
	if len(servers) != 1 {
		t.Errorf("expected 1 server in JSON, got %d", len(servers))
	}
}

func TestE2E_TextOutput(t *testing.T) {
	configPath := writeConfig(t, "weather", weatherServerBin)
	results := runPipeline(t, configPath, false)

	var buf bytes.Buffer
	formatter := output.NewTextFormatter(&buf)
	opts := output.FormatOptions{PrintErrors: true}
	if err := formatter.FormatResults(results, opts); err != nil {
		t.Fatalf("text format error: %v", err)
	}

	text := buf.String()

	// Verify output contains key strings.
	for _, want := range []string{
		"weather",
		"get_weather",
		"get_forecast",
		"Scanned",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text output missing expected string %q", want)
		}
	}

	t.Logf("text output:\n%s", text)
}
