package inspect

import (
	"path/filepath"
	"runtime"
	"testing"
)

func testdataPath(parts ...string) string {
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	base := filepath.Join(dir, "..", "..", "testdata")
	return filepath.Join(append([]string{base}, parts...)...)
}

func TestParseSkillDirectory_Testdata_Valid(t *testing.T) {
	path := testdataPath("skills", "valid-skill")
	sig, err := ParseSkillDirectory(path)
	if err != nil {
		t.Fatal(err)
	}

	if sig.Metadata.ServerInfo.Name != "code-review" {
		t.Errorf("expected name='code-review', got %s", sig.Metadata.ServerInfo.Name)
	}

	// Expect: SKILL.md prompt + templates/review.md prompt = 2 prompts
	if len(sig.Prompts) < 2 {
		t.Errorf("expected at least 2 prompts, got %d", len(sig.Prompts))
	}

	// Expect: helpers/lint.py = 1 tool
	if len(sig.Tools) < 1 {
		t.Errorf("expected at least 1 tool, got %d", len(sig.Tools))
	}
}

func TestParseSkillDirectory_Testdata_Malicious(t *testing.T) {
	path := testdataPath("skills", "malicious-skill")
	sig, err := ParseSkillDirectory(path)
	if err != nil {
		t.Fatal(err)
	}

	if sig.Metadata.ServerInfo.Name != "helpful-assistant" {
		t.Errorf("expected name='helpful-assistant', got %s", sig.Metadata.ServerInfo.Name)
	}

	// The SKILL.md content contains prompt injection patterns
	// that should be detected by the rules engine
	if len(sig.Prompts) == 0 {
		t.Error("expected at least 1 prompt from malicious skill")
	}
}

func TestParseSkillDirectory_Testdata_NoSkillMD(t *testing.T) {
	path := testdataPath("skills", "no-skillmd")
	_, err := ParseSkillDirectory(path)
	if err == nil {
		t.Error("expected error for directory without SKILL.md")
	}
}
