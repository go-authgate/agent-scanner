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

func TestParseSkillDirectory_Testdata_MaliciousTrading(t *testing.T) {
	path := testdataPath("skills", "malicious-skill-trading")
	sig, err := ParseSkillDirectory(path)
	if err != nil {
		t.Fatal(err)
	}

	if sig.Metadata.ServerInfo.Name != "base-trading-agent" {
		t.Errorf("expected name='base-trading-agent', got %s", sig.Metadata.ServerInfo.Name)
	}

	if len(sig.Prompts) == 0 {
		t.Error("expected at least 1 prompt from malicious trading skill")
	}
}

func TestParseSkillDirectory_Testdata_InternalComms(t *testing.T) {
	path := testdataPath("skills", "internal-comms")
	sig, err := ParseSkillDirectory(path)
	if err != nil {
		t.Fatal(err)
	}

	if sig.Metadata.ServerInfo.Name != "internal-comms" {
		t.Errorf("expected name='internal-comms', got %s", sig.Metadata.ServerInfo.Name)
	}

	// Expect: SKILL.md prompt + 4 examples/*.md prompts = 5 prompts
	if len(sig.Prompts) < 5 {
		t.Errorf("expected at least 5 prompts, got %d", len(sig.Prompts))
	}

	// No .py/.js/.ts/.sh files → 0 tools
	if len(sig.Tools) != 0 {
		t.Errorf("expected 0 tools, got %d", len(sig.Tools))
	}

	// LICENSE.txt → 1 resource
	if len(sig.Resources) < 1 {
		t.Errorf("expected at least 1 resource (LICENSE.txt), got %d", len(sig.Resources))
	}
}

func TestParseSkillDirectory_Testdata_AlgorithmicArt(t *testing.T) {
	path := testdataPath("skills", "algorithmic-art")
	sig, err := ParseSkillDirectory(path)
	if err != nil {
		t.Fatal(err)
	}

	if sig.Metadata.ServerInfo.Name != "algorithmic-art" {
		t.Errorf("expected name='algorithmic-art', got %s", sig.Metadata.ServerInfo.Name)
	}

	// Expect: SKILL.md prompt = at least 1 prompt
	if len(sig.Prompts) < 1 {
		t.Errorf("expected at least 1 prompt, got %d", len(sig.Prompts))
	}

	// templates/generator_template.js → 1 tool
	if len(sig.Tools) < 1 {
		t.Errorf("expected at least 1 tool (generator_template.js), got %d", len(sig.Tools))
	}

	// LICENSE.txt + templates/viewer.html = at least 2 resources
	if len(sig.Resources) < 2 {
		t.Errorf("expected at least 2 resources, got %d", len(sig.Resources))
	}
}
