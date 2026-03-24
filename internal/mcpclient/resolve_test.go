package mcpclient

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveCommand_FoundInPath(t *testing.T) {
	// "ls" (or "cmd" on Windows) should always be resolvable via PATH.
	cmd := "ls"
	if isWindows() {
		cmd = "cmd"
	}

	path, err := resolveCommand(cmd)
	if err != nil {
		t.Fatalf("expected resolveCommand(%q) to succeed, got error: %v", cmd, err)
	}
	if path == "" {
		t.Fatalf("expected non-empty path for %q", cmd)
	}
}

func TestResolveCommand_NotFound(t *testing.T) {
	_, err := resolveCommand("__nonexistent_binary_xyz_123__")
	if err == nil {
		t.Fatal("expected error for nonexistent command, got nil")
	}
}

func TestResolveCommand_FallbackDir(t *testing.T) {
	// Create a temporary directory that mimics a fallback location and
	// place a fake executable there.
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, ".cargo", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}

	fakeCmd := "fake-scanner-test-cmd"
	fakePath := filepath.Join(binDir, fakeCmd)
	if err := os.WriteFile(fakePath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// searchFallbackDirs should find it when home is set to tmpDir.
	found := searchFallbackDirs(fakeCmd, tmpDir)
	if found == "" {
		t.Fatalf("expected searchFallbackDirs to find %q in %s", fakeCmd, binDir)
	}
	if found != fakePath {
		t.Errorf("expected %s, got %s", fakePath, found)
	}
}

func TestSearchFallbackDirs_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	found := searchFallbackDirs("__no_such_cmd__", tmpDir)
	if found != "" {
		t.Errorf("expected empty string, got %s", found)
	}
}

func TestIsExecutable(t *testing.T) {
	tmpDir := t.TempDir()

	// Non-executable file
	nonExec := filepath.Join(tmpDir, "noexec")
	if err := os.WriteFile(nonExec, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if isExecutable(nonExec) {
		t.Error("expected non-executable file to return false")
	}

	// Executable file
	execFile := filepath.Join(tmpDir, "yesexec")
	if err := os.WriteFile(execFile, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !isExecutable(execFile) {
		t.Error("expected executable file to return true")
	}

	// Directory should return false
	if isExecutable(tmpDir) {
		t.Error("expected directory to return false")
	}

	// Non-existent path should return false
	if isExecutable(filepath.Join(tmpDir, "missing")) {
		t.Error("expected non-existent path to return false")
	}
}

func isWindows() bool {
	return filepath.Separator == '\\'
}
