package mcpserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultConfigPath(t *testing.T) {
	path, err := DefaultConfigPath()
	if err != nil {
		t.Fatalf("DefaultConfigPath failed: %v", err)
	}

	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "darwin":
		expected := filepath.Join(
			home,
			"Library",
			"Application Support",
			"Claude",
			"claude_desktop_config.json",
		)
		if path != expected {
			t.Errorf("expected %q, got %q", expected, path)
		}
	case "linux":
		expected := filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
		if path != expected {
			t.Errorf("expected %q, got %q", expected, path)
		}
	case "windows":
		expected := filepath.Join(
			home,
			"AppData",
			"Roaming",
			"Claude",
			"claude_desktop_config.json",
		)
		if path != expected {
			t.Errorf("expected %q, got %q", expected, path)
		}
	}
}

func TestInstallServer_NewConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	if err := InstallServer(configPath); err != nil {
		t.Fatalf("InstallServer failed: %v", err)
	}

	// Verify the file was created
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading config file failed: %v", err)
	}

	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("parsing config file failed: %v", err)
	}

	mcpServers, ok := config["mcpServers"].(map[string]any)
	if !ok {
		t.Fatal("expected mcpServers key in config")
	}

	entry, ok := mcpServers["agent-scanner"].(map[string]any)
	if !ok {
		t.Fatal("expected agent-scanner entry in mcpServers")
	}

	if _, ok := entry["command"].(string); !ok {
		t.Error("expected command field in agent-scanner entry")
	}

	args, ok := entry["args"].([]any)
	if !ok {
		t.Fatal("expected args field in agent-scanner entry")
	}
	if len(args) != 1 || args[0] != "mcp-server" {
		t.Errorf("expected args [\"mcp-server\"], got %v", args)
	}
}

func TestInstallServer_ExistingConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	// Create existing config with another server
	existingConfig := map[string]any{
		"mcpServers": map[string]any{
			"existing-server": map[string]any{
				"command": "existing-cmd",
				"args":    []string{"--existing"},
			},
		},
		"otherKey": "otherValue",
	}
	data, _ := json.MarshalIndent(existingConfig, "", "  ")
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		t.Fatalf("writing existing config failed: %v", err)
	}

	if err := InstallServer(configPath); err != nil {
		t.Fatalf("InstallServer failed: %v", err)
	}

	// Verify existing entries are preserved
	updatedData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading updated config failed: %v", err)
	}

	var config map[string]any
	if err := json.Unmarshal(updatedData, &config); err != nil {
		t.Fatalf("parsing updated config failed: %v", err)
	}

	// Check other keys are preserved
	if config["otherKey"] != "otherValue" {
		t.Error("existing config key 'otherKey' was not preserved")
	}

	mcpServers := config["mcpServers"].(map[string]any)

	// Check existing server is preserved
	if _, ok := mcpServers["existing-server"]; !ok {
		t.Error("existing-server entry was not preserved")
	}

	// Check agent-scanner was added
	if _, ok := mcpServers["agent-scanner"]; !ok {
		t.Error("agent-scanner entry was not added")
	}
}

func TestInstallServer_NestedDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "subdir", "nested", "config.json")

	if err := InstallServer(configPath); err != nil {
		t.Fatalf("InstallServer failed for nested path: %v", err)
	}

	// Verify the file was created
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("config file was not created in nested directory")
	}
}

func TestInstallServer_UpdateExistingEntry(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	// Create config with an old agent-scanner entry
	existingConfig := map[string]any{
		"mcpServers": map[string]any{
			"agent-scanner": map[string]any{
				"command": "/old/path/agent-scanner",
				"args":    []string{"mcp-server", "--old-flag"},
			},
		},
	}
	data, _ := json.MarshalIndent(existingConfig, "", "  ")
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		t.Fatalf("writing existing config failed: %v", err)
	}

	if err := InstallServer(configPath); err != nil {
		t.Fatalf("InstallServer failed: %v", err)
	}

	// Verify the entry was updated
	updatedData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("reading updated config failed: %v", err)
	}

	var config map[string]any
	if err := json.Unmarshal(updatedData, &config); err != nil {
		t.Fatalf("parsing updated config failed: %v", err)
	}

	mcpServers := config["mcpServers"].(map[string]any)
	entry := mcpServers["agent-scanner"].(map[string]any)

	args := entry["args"].([]any)
	if len(args) != 1 || args[0] != "mcp-server" {
		t.Errorf("expected updated args [\"mcp-server\"], got %v", args)
	}
}
