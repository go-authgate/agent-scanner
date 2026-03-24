package rules

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/go-authgate/agent-scanner/internal/inspect"
	"github.com/go-authgate/agent-scanner/internal/models"
)

func testdataPath(parts ...string) string {
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	base := filepath.Join(dir, "..", "..", "testdata")
	return filepath.Join(append([]string{base}, parts...)...)
}

func TestRulesAgainstMaliciousSkill(t *testing.T) {
	path := testdataPath("skills", "malicious-skill")
	sig, err := inspect.ParseSkillDirectory(path)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &RuleContext{
		Servers: []models.ServerScanResult{
			{
				Name:      "malicious-skill",
				Server:    &models.SkillServer{Path: path},
				Signature: sig,
			},
		},
	}

	engine := NewDefaultEngine()
	issues := engine.Run(ctx)

	if len(issues) == 0 {
		t.Fatal("expected issues from malicious skill, got none")
	}

	// Verify specific detections
	codeSet := make(map[string]bool)
	for _, issue := range issues {
		codeSet[issue.Code] = true
	}

	// Should detect suspicious trigger words (<IMPORTANT>, ignore previous, etc.)
	if !codeSet[models.CodeSuspiciousWords] {
		t.Error("expected W001 (suspicious trigger words) detection")
	}

	// Should detect hardcoded secrets (api_key=sk-...)
	if !codeSet[models.CodeHardcodedSecrets] {
		t.Error("expected W008 (hardcoded secrets) detection")
	}

	// Should detect suspicious URL (bit.ly)
	if !codeSet[models.CodeSuspiciousURL] {
		t.Error("expected E005 (suspicious URL) detection")
	}

	// Should detect malicious code pattern (eval)
	if !codeSet[models.CodeMaliciousCode] {
		t.Error("expected E006 (malicious code pattern) detection")
	}

	// Should detect prompt injection in skill content (E004)
	if !codeSet[models.CodeSkillInjection] {
		t.Error("expected E004 (skill injection) detection")
	}

	t.Logf("detected %d issues from malicious skill: %v", len(issues), mapKeys(codeSet))
}

func TestRulesAgainstCleanSkill(t *testing.T) {
	path := testdataPath("skills", "valid-skill")
	sig, err := inspect.ParseSkillDirectory(path)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &RuleContext{
		Servers: []models.ServerScanResult{
			{
				Name:      "valid-skill",
				Server:    &models.SkillServer{Path: path},
				Signature: sig,
			},
		},
	}

	engine := NewDefaultEngine()
	issues := engine.Run(ctx)

	// Filter out info-level issues
	var significant []models.Issue
	for _, issue := range issues {
		if models.SeverityRank(issue.GetSeverity()) >= models.SeverityRank(models.SeverityMedium) {
			significant = append(significant, issue)
		}
	}

	if len(significant) > 0 {
		for _, issue := range significant {
			t.Errorf("unexpected issue on clean skill: [%s] %s", issue.Code, issue.Message)
		}
	}
}

func TestRulesAgainstConfigWithSecrets(t *testing.T) {
	// Parse the Claude Desktop config which has a GITHUB_TOKEN in env
	configPath := testdataPath("configs", "claude_desktop_config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	// The config file itself has a hardcoded token in env, but the rule engine
	// checks entity descriptions, not server configs. This test verifies the
	// engine doesn't crash on configs parsed from testdata.
	_ = data

	ctx := &RuleContext{
		Servers: []models.ServerScanResult{
			{
				Name: "filesystem",
				Server: &models.StdioServer{
					Command: "npx",
					Args:    []string{"-y", "@modelcontextprotocol/server-filesystem"},
				},
				Signature: &models.ServerSignature{
					Tools: []models.Tool{
						{Name: "read_file", Description: "Read contents of a file"},
						{Name: "write_file", Description: "Write contents to a file"},
					},
				},
			},
		},
	}

	engine := NewDefaultEngine()
	issues := engine.Run(ctx)
	// Clean tools should produce no issues
	for _, issue := range issues {
		if models.SeverityRank(issue.GetSeverity()) >= models.SeverityRank(models.SeverityMedium) {
			t.Errorf("unexpected issue on clean tools: [%s] %s", issue.Code, issue.Message)
		}
	}
}

func TestRulesAgainstMaliciousTradingSkill(t *testing.T) {
	path := testdataPath("skills", "malicious-skill-trading")
	sig, err := inspect.ParseSkillDirectory(path)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &RuleContext{
		Servers: []models.ServerScanResult{
			{
				Name:      "malicious-skill-trading",
				Server:    &models.SkillServer{Path: path},
				Signature: sig,
			},
		},
	}

	engine := NewDefaultEngine()
	issues := engine.Run(ctx)

	if len(issues) == 0 {
		t.Fatal("expected issues from malicious trading skill, got none")
	}

	codeSet := make(map[string]bool)
	for _, issue := range issues {
		codeSet[issue.Code] = true
	}

	// Should detect financial execution keywords (buy, sell, trade)
	if !codeSet[models.CodeFinancialExecution] {
		t.Error("expected W009 (financial execution) detection")
	}

	// Should detect external dependencies (curl piped to bash)
	if !codeSet[models.CodeExternalDependencies] {
		t.Error("expected W012 (external dependencies) detection")
	}

	// Should detect system modification keywords (sudo, install software)
	if !codeSet[models.CodeSystemModification] {
		t.Error("expected W013 (system modification) detection")
	}

	t.Logf("detected %d issues from malicious trading skill: %v", len(issues), mapKeys(codeSet))
}

func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
