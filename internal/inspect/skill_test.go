package inspect

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParseSkillDirectory(t *testing.T) {
	dir := t.TempDir()

	// Create SKILL.md
	skillContent := `---
name: my-skill
description: A test skill
---

This is the skill body content.
`
	if err := os.WriteFile(
		filepath.Join(dir, "SKILL.md"),
		[]byte(skillContent),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	// Create a sub-file
	if err := os.WriteFile(
		filepath.Join(dir, "helper.py"),
		[]byte("def help(): pass"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	sig, err := ParseSkillDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}

	if sig.Metadata.ServerInfo.Name != "my-skill" {
		t.Errorf("expected name=my-skill, got %s", sig.Metadata.ServerInfo.Name)
	}

	// Should have the SKILL.md prompt + helper.py tool
	if len(sig.Prompts) < 1 {
		t.Error("expected at least 1 prompt")
	}
	if len(sig.Tools) < 1 {
		t.Error("expected at least 1 tool from helper.py")
	}
}

func TestParseSkillDirectory_NoSkillMD(t *testing.T) {
	dir := t.TempDir()
	_, err := ParseSkillDirectory(dir)
	if err == nil {
		t.Error("expected error for missing SKILL.md")
	}
}

func TestParseSkillFrontmatter(t *testing.T) {
	tests := []struct {
		content  string
		wantName string
		wantDesc string
	}{
		{
			content:  "---\nname: test\ndescription: A test\n---\nBody content",
			wantName: "test",
			wantDesc: "A test\n\nBody content",
		},
		{
			content:  "---\nname: \"quoted-name\"\n---\nBody here",
			wantName: "quoted-name",
			wantDesc: "Body here",
		},
		{
			content:  "No frontmatter here",
			wantName: "",
			wantDesc: "No frontmatter here",
		},
	}

	for _, tt := range tests {
		name, desc := parseSkillFrontmatter(tt.content)
		if name != tt.wantName {
			t.Errorf("parseSkillFrontmatter name = %q, want %q", name, tt.wantName)
		}
		if desc != tt.wantDesc {
			t.Errorf("parseSkillFrontmatter desc = %q, want %q", desc, tt.wantDesc)
		}
	}
}

func TestTraverseSkillTree(t *testing.T) {
	dir := t.TempDir()

	// Resolve symlinks (e.g. macOS /var → /private/var) so basePath
	// matches what ParseSkillDirectory would produce.
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Create files of different types
	os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: test\n---"), 0o644)
	os.WriteFile(filepath.Join(dir, "readme.md"), []byte("# Readme"), 0o644)
	os.WriteFile(filepath.Join(dir, "script.py"), []byte("print('hello')"), 0o644)
	os.WriteFile(filepath.Join(dir, "data.json"), []byte("{}"), 0o644)

	prompts, resources, tools := traverseSkillTree(dir, "")

	if len(prompts) != 1 { // readme.md (SKILL.md is skipped)
		t.Errorf("expected 1 prompt, got %d", len(prompts))
	}
	if len(tools) != 1 { // script.py
		t.Errorf("expected 1 tool, got %d", len(tools))
	}
	if len(resources) != 1 { // data.json
		t.Errorf("expected 1 resource, got %d", len(resources))
	}
}

func TestTraverseSkillTree_SymlinkOutsideBase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test not supported on Windows")
	}

	// Create a skill directory and an outside directory with a secret file
	skillDir := t.TempDir()
	outsideDir := t.TempDir()

	os.WriteFile(filepath.Join(outsideDir, "secret.py"), []byte("SECRET_KEY='abc'"), 0o644)

	// Create a symlink inside the skill directory pointing outside
	symlinkPath := filepath.Join(skillDir, "escape")
	if err := os.Symlink(outsideDir, symlinkPath); err != nil {
		t.Fatal(err)
	}

	// Resolve basePath like ParseSkillDirectory does
	resolvedBase, err := filepath.EvalSymlinks(skillDir)
	if err != nil {
		t.Fatal(err)
	}

	prompts, _, tools := traverseSkillTree(resolvedBase, "")

	// The symlinked directory should be skipped — no tools from outside
	for _, tool := range tools {
		if tool.Name == "escape/secret.py" || tool.Description == "SECRET_KEY='abc'" {
			t.Error("symlinked file outside base was included as a tool")
		}
	}
	for _, prompt := range prompts {
		if prompt.Description == "SECRET_KEY='abc'" {
			t.Error("symlinked file outside base was included as a prompt")
		}
	}
}

func TestIsWithinBase(t *testing.T) {
	tests := []struct {
		base, path string
		want       bool
	}{
		{"/a/b", "/a/b", true},
		{"/a/b", "/a/b/c", true},
		{"/a/b", "/a/b/c/d", true},
		{"/a/b", "/a/bc", false},
		{"/a/b", "/a", false},
		{"/a/b", "/x/y", false},
	}
	for _, tt := range tests {
		got := isWithinBase(tt.base, tt.path)
		if got != tt.want {
			t.Errorf("isWithinBase(%q, %q) = %v, want %v", tt.base, tt.path, got, tt.want)
		}
	}
}
