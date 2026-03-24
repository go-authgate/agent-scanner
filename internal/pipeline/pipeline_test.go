package pipeline

import (
	"context"
	"errors"
	"testing"

	"github.com/go-authgate/agent-scanner/internal/models"
	"github.com/go-authgate/agent-scanner/internal/rules"
)

// --- Mock types ---

type mockDiscoverer struct {
	discoverClientsFn func(ctx context.Context, allUsers bool) []models.CandidateClient
	resolveClientFn   func(ctx context.Context, candidate models.CandidateClient) ([]*models.ClientToInspect, error)
	clientFromPathFn  func(ctx context.Context, path string, scanSkills bool) ([]*models.ClientToInspect, error)
}

func (m *mockDiscoverer) DiscoverClients(
	ctx context.Context,
	allUsers bool,
) []models.CandidateClient {
	if m.discoverClientsFn != nil {
		return m.discoverClientsFn(ctx, allUsers)
	}
	return nil
}

func (m *mockDiscoverer) ResolveClient(
	ctx context.Context,
	candidate models.CandidateClient,
) ([]*models.ClientToInspect, error) {
	if m.resolveClientFn != nil {
		return m.resolveClientFn(ctx, candidate)
	}
	return []*models.ClientToInspect{}, nil
}

func (m *mockDiscoverer) ClientFromPath(
	ctx context.Context,
	path string,
	scanSkills bool,
) ([]*models.ClientToInspect, error) {
	if m.clientFromPathFn != nil {
		return m.clientFromPathFn(ctx, path, scanSkills)
	}
	return []*models.ClientToInspect{}, nil
}

type mockInspector struct {
	inspectClientFn func(ctx context.Context, client *models.ClientToInspect, scanSkills bool) (*models.InspectedClient, error)
}

func (m *mockInspector) InspectServer(
	_ context.Context,
	_ string,
	_ models.ServerConfig,
) (*models.InspectedExtension, error) {
	return &models.InspectedExtension{}, nil
}

func (m *mockInspector) InspectSkill(
	_ context.Context,
	_ string,
	_ *models.SkillServer,
) (*models.InspectedExtension, error) {
	return &models.InspectedExtension{}, nil
}

func (m *mockInspector) InspectClient(
	ctx context.Context,
	client *models.ClientToInspect,
	scanSkills bool,
) (*models.InspectedClient, error) {
	if m.inspectClientFn != nil {
		return m.inspectClientFn(ctx, client, scanSkills)
	}
	return &models.InspectedClient{
		Name:       client.Name,
		Extensions: map[string][]models.InspectedExtension{},
	}, nil
}

type mockRuleEngine struct {
	runFn func(ctx *rules.RuleContext) []models.Issue
}

func (m *mockRuleEngine) Register(_ rules.Rule) {}

func (m *mockRuleEngine) Run(ctx *rules.RuleContext) []models.Issue {
	if m.runFn != nil {
		return m.runFn(ctx)
	}
	return nil
}

type mockAnalyzer struct {
	analyzeFn func(ctx context.Context, results []models.ScanPathResult) ([]models.ScanPathResult, error)
	called    bool
}

func (m *mockAnalyzer) Analyze(
	ctx context.Context,
	results []models.ScanPathResult,
) ([]models.ScanPathResult, error) {
	m.called = true
	if m.analyzeFn != nil {
		return m.analyzeFn(ctx, results)
	}
	return results, nil
}

type mockUploader struct {
	uploadFn func(ctx context.Context, results []models.ScanPathResult, server models.ControlServer) error
	called   bool
	servers  []models.ControlServer
}

func (m *mockUploader) Upload(
	ctx context.Context,
	results []models.ScanPathResult,
	server models.ControlServer,
) error {
	m.called = true
	m.servers = append(m.servers, server)
	if m.uploadFn != nil {
		return m.uploadFn(ctx, results, server)
	}
	return nil
}

// --- Helpers ---

// newTestClient returns a simple ClientToInspect for testing.
func newTestClient(name string) *models.ClientToInspect {
	return &models.ClientToInspect{
		Name:       name,
		MCPConfigs: map[string]models.MCPConfigOrError{},
	}
}

// newInspectedClient returns an InspectedClient with one extension under a config path.
func newInspectedClient(name, configPath, extName string) *models.InspectedClient {
	return &models.InspectedClient{
		Name: name,
		Extensions: map[string][]models.InspectedExtension{
			configPath: {
				{
					Name:   extName,
					Config: &models.StdioServer{Command: "echo"},
					Signature: &models.ServerSignature{
						Tools: []models.Tool{{Name: "test-tool", Description: "a test tool"}},
					},
				},
			},
		},
	}
}

// --- Tests ---

func TestRun_InspectOnly(t *testing.T) {
	disc := &mockDiscoverer{
		discoverClientsFn: func(_ context.Context, _ bool) []models.CandidateClient {
			return []models.CandidateClient{{Name: "test-client"}}
		},
		resolveClientFn: func(_ context.Context, c models.CandidateClient) ([]*models.ClientToInspect, error) {
			return []*models.ClientToInspect{newTestClient(c.Name)}, nil
		},
	}
	insp := &mockInspector{
		inspectClientFn: func(_ context.Context, client *models.ClientToInspect, _ bool) (*models.InspectedClient, error) {
			return newInspectedClient(client.Name, "/config.json", "server-a"), nil
		},
	}
	analyzer := &mockAnalyzer{}
	uploader := &mockUploader{}

	p := New(Config{
		Discoverer:  disc,
		Inspector:   insp,
		Analyzer:    analyzer,
		Uploader:    uploader,
		InspectOnly: true,
		ControlServers: []ControlServerConfig{
			{URL: "https://control.example.com"},
		},
	})

	results, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result from inspect stage")
	}
	if analyzer.called {
		t.Error("analyzer should NOT be called in InspectOnly mode")
	}
	if uploader.called {
		t.Error("uploader should NOT be called in InspectOnly mode")
	}
}

func TestRun_FullPipeline(t *testing.T) {
	discoverCalled := false
	resolveCalled := false

	disc := &mockDiscoverer{
		discoverClientsFn: func(_ context.Context, _ bool) []models.CandidateClient {
			discoverCalled = true
			return []models.CandidateClient{{Name: "claude"}}
		},
		resolveClientFn: func(_ context.Context, c models.CandidateClient) ([]*models.ClientToInspect, error) {
			resolveCalled = true
			return []*models.ClientToInspect{newTestClient(c.Name)}, nil
		},
	}
	insp := &mockInspector{
		inspectClientFn: func(_ context.Context, client *models.ClientToInspect, _ bool) (*models.InspectedClient, error) {
			return newInspectedClient(client.Name, "/config.json", "srv"), nil
		},
	}

	ruleEngine := &mockRuleEngine{
		runFn: func(_ *rules.RuleContext) []models.Issue {
			return []models.Issue{{Code: "W001", Message: "suspicious"}}
		},
	}

	analyzer := &mockAnalyzer{
		analyzeFn: func(_ context.Context, results []models.ScanPathResult) ([]models.ScanPathResult, error) {
			// Simulate adding labels
			for i := range results {
				results[i].Labels = [][]models.ScalarToolLabels{{{IsPublicSink: 0.9}}}
			}
			return results, nil
		},
	}

	uploader := &mockUploader{}

	p := New(Config{
		Discoverer: disc,
		Inspector:  insp,
		RuleEngine: ruleEngine,
		Analyzer:   analyzer,
		Uploader:   uploader,
		ControlServers: []ControlServerConfig{
			{URL: "https://ctrl.example.com", Identifier: "id-1"},
		},
	})

	results, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !discoverCalled {
		t.Error("DiscoverClients should be called when no Paths are set")
	}
	if !resolveCalled {
		t.Error("ResolveClient should be called when no Paths are set")
	}
	if !analyzer.called {
		t.Error("analyzer should be called in full pipeline")
	}
	if !uploader.called {
		t.Error("uploader should be called in full pipeline")
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	// Check that rule engine issues were appended.
	foundIssue := false
	for _, r := range results {
		for _, iss := range r.Issues {
			if iss.Code == "W001" {
				foundIssue = true
			}
		}
	}
	if !foundIssue {
		t.Error("expected rule engine issue W001 in results")
	}
	// Check that uploader received the correct server.
	if len(uploader.servers) != 1 {
		t.Fatalf("expected uploader to be called once, got %d", len(uploader.servers))
	}
	if uploader.servers[0].URL != "https://ctrl.example.com" {
		t.Errorf("unexpected control server URL: %s", uploader.servers[0].URL)
	}
	if uploader.servers[0].Identifier != "id-1" {
		t.Errorf("unexpected control server identifier: %s", uploader.servers[0].Identifier)
	}
}

func TestRun_WithPaths_UsesClientFromPath(t *testing.T) {
	clientFromPathCalled := false
	discoverClientsCalled := false

	disc := &mockDiscoverer{
		discoverClientsFn: func(_ context.Context, _ bool) []models.CandidateClient {
			discoverClientsCalled = true
			return nil
		},
		clientFromPathFn: func(_ context.Context, path string, _ bool) ([]*models.ClientToInspect, error) {
			clientFromPathCalled = true
			return []*models.ClientToInspect{newTestClient("path-client-" + path)}, nil
		},
	}
	insp := &mockInspector{
		inspectClientFn: func(_ context.Context, client *models.ClientToInspect, _ bool) (*models.InspectedClient, error) {
			return newInspectedClient(client.Name, "/some/path", "ext"), nil
		},
	}

	p := New(Config{
		Discoverer:  disc,
		Inspector:   insp,
		Paths:       []string{"/path/to/config.json", "/another/config.json"},
		InspectOnly: true,
	})

	results, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !clientFromPathCalled {
		t.Error("ClientFromPath should be called when Paths are provided")
	}
	if discoverClientsCalled {
		t.Error("DiscoverClients should NOT be called when Paths are provided")
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results (one per path), got %d", len(results))
	}
}

func TestRun_NoPaths_UsesDiscoverAndResolve(t *testing.T) {
	discoverCalled := false
	resolveCalled := false
	clientFromPathCalled := false

	disc := &mockDiscoverer{
		discoverClientsFn: func(_ context.Context, _ bool) []models.CandidateClient {
			discoverCalled = true
			return []models.CandidateClient{
				{Name: "client-a"},
				{Name: "client-b"},
			}
		},
		resolveClientFn: func(_ context.Context, c models.CandidateClient) ([]*models.ClientToInspect, error) {
			resolveCalled = true
			return []*models.ClientToInspect{newTestClient(c.Name)}, nil
		},
		clientFromPathFn: func(_ context.Context, _ string, _ bool) ([]*models.ClientToInspect, error) {
			clientFromPathCalled = true
			return nil, nil
		},
	}
	insp := &mockInspector{
		inspectClientFn: func(_ context.Context, client *models.ClientToInspect, _ bool) (*models.InspectedClient, error) {
			return newInspectedClient(client.Name, "/cfg", "ext"), nil
		},
	}

	p := New(Config{
		Discoverer:  disc,
		Inspector:   insp,
		InspectOnly: true,
	})

	results, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !discoverCalled {
		t.Error("DiscoverClients should be called")
	}
	if !resolveCalled {
		t.Error("ResolveClient should be called")
	}
	if clientFromPathCalled {
		t.Error("ClientFromPath should NOT be called when no Paths are set")
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results (one per discovered client), got %d", len(results))
	}
}

func TestRun_NilAnalyzer_SkipsAnalysis(t *testing.T) {
	disc := &mockDiscoverer{
		discoverClientsFn: func(_ context.Context, _ bool) []models.CandidateClient {
			return []models.CandidateClient{{Name: "c"}}
		},
		resolveClientFn: func(_ context.Context, c models.CandidateClient) ([]*models.ClientToInspect, error) {
			return []*models.ClientToInspect{newTestClient(c.Name)}, nil
		},
	}
	insp := &mockInspector{
		inspectClientFn: func(_ context.Context, client *models.ClientToInspect, _ bool) (*models.InspectedClient, error) {
			return newInspectedClient(client.Name, "/cfg", "ext"), nil
		},
	}

	ruleEngine := &mockRuleEngine{
		runFn: func(_ *rules.RuleContext) []models.Issue {
			return []models.Issue{{Code: "W002", Message: "too many entities"}}
		},
	}

	p := New(Config{
		Discoverer: disc,
		Inspector:  insp,
		RuleEngine: ruleEngine,
		Analyzer:   nil, // nil analyzer
	})

	results, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected results")
	}
	// Rule engine should still have run.
	foundIssue := false
	for _, r := range results {
		for _, iss := range r.Issues {
			if iss.Code == "W002" {
				foundIssue = true
			}
		}
	}
	if !foundIssue {
		t.Error("expected rule engine issue W002 even with nil analyzer")
	}
}

func TestRun_NilUploader_SkipsPush(t *testing.T) {
	disc := &mockDiscoverer{
		discoverClientsFn: func(_ context.Context, _ bool) []models.CandidateClient {
			return []models.CandidateClient{{Name: "c"}}
		},
		resolveClientFn: func(_ context.Context, c models.CandidateClient) ([]*models.ClientToInspect, error) {
			return []*models.ClientToInspect{newTestClient(c.Name)}, nil
		},
	}
	insp := &mockInspector{
		inspectClientFn: func(_ context.Context, client *models.ClientToInspect, _ bool) (*models.InspectedClient, error) {
			return newInspectedClient(client.Name, "/cfg", "ext"), nil
		},
	}

	// nil Uploader, with ControlServers configured
	p := New(Config{
		Discoverer: disc,
		Inspector:  insp,
		Uploader:   nil,
		ControlServers: []ControlServerConfig{
			{URL: "https://ctrl.example.com"},
		},
	})

	// Should not panic.
	_, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_EmptyControlServers_SkipsPush(t *testing.T) {
	disc := &mockDiscoverer{
		discoverClientsFn: func(_ context.Context, _ bool) []models.CandidateClient {
			return []models.CandidateClient{{Name: "c"}}
		},
		resolveClientFn: func(_ context.Context, c models.CandidateClient) ([]*models.ClientToInspect, error) {
			return []*models.ClientToInspect{newTestClient(c.Name)}, nil
		},
	}
	insp := &mockInspector{
		inspectClientFn: func(_ context.Context, client *models.ClientToInspect, _ bool) (*models.InspectedClient, error) {
			return newInspectedClient(client.Name, "/cfg", "ext"), nil
		},
	}

	uploader := &mockUploader{}

	// Uploader provided, but no ControlServers
	p := New(Config{
		Discoverer:     disc,
		Inspector:      insp,
		Uploader:       uploader,
		ControlServers: nil,
	})

	_, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if uploader.called {
		t.Error("uploader should NOT be called with empty ControlServers")
	}
}

func TestRun_ClientDiscoveryFailure_Continues(t *testing.T) {
	resolveCallCount := 0
	disc := &mockDiscoverer{
		discoverClientsFn: func(_ context.Context, _ bool) []models.CandidateClient {
			return []models.CandidateClient{
				{Name: "failing-client"},
				{Name: "ok-client"},
			}
		},
		resolveClientFn: func(_ context.Context, c models.CandidateClient) ([]*models.ClientToInspect, error) {
			resolveCallCount++
			if c.Name == "failing-client" {
				return nil, errors.New("resolution failed")
			}
			return []*models.ClientToInspect{newTestClient(c.Name)}, nil
		},
	}
	insp := &mockInspector{
		inspectClientFn: func(_ context.Context, client *models.ClientToInspect, _ bool) (*models.InspectedClient, error) {
			return newInspectedClient(client.Name, "/cfg", "ext"), nil
		},
	}

	p := New(Config{
		Discoverer:  disc,
		Inspector:   insp,
		InspectOnly: true,
	})

	results, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resolveCallCount != 2 {
		t.Errorf("expected ResolveClient to be called 2 times, got %d", resolveCallCount)
	}

	// Only the successful client should produce results.
	if len(results) != 1 {
		t.Errorf("expected 1 result from the successful client, got %d", len(results))
	}
	if len(results) > 0 && results[0].Client != "ok-client" {
		t.Errorf("expected result from ok-client, got %q", results[0].Client)
	}
}

func TestRun_ClientFromPathFailure_Continues(t *testing.T) {
	disc := &mockDiscoverer{
		clientFromPathFn: func(_ context.Context, path string, _ bool) ([]*models.ClientToInspect, error) {
			if path == "/bad/path" {
				return nil, errors.New("path not found")
			}
			return []*models.ClientToInspect{newTestClient("good-client")}, nil
		},
	}
	insp := &mockInspector{
		inspectClientFn: func(_ context.Context, client *models.ClientToInspect, _ bool) (*models.InspectedClient, error) {
			return newInspectedClient(client.Name, "/cfg", "ext"), nil
		},
	}

	p := New(Config{
		Discoverer:  disc,
		Inspector:   insp,
		Paths:       []string{"/bad/path", "/good/path"},
		InspectOnly: true,
	})

	results, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only the good path should produce results.
	if len(results) != 1 {
		t.Errorf("expected 1 result from the good path, got %d", len(results))
	}
}

func TestRun_InspectClientFailure_Continues(t *testing.T) {
	disc := &mockDiscoverer{
		discoverClientsFn: func(_ context.Context, _ bool) []models.CandidateClient {
			return []models.CandidateClient{
				{Name: "fail-inspect"},
				{Name: "ok-inspect"},
			}
		},
		resolveClientFn: func(_ context.Context, c models.CandidateClient) ([]*models.ClientToInspect, error) {
			return []*models.ClientToInspect{newTestClient(c.Name)}, nil
		},
	}
	insp := &mockInspector{
		inspectClientFn: func(_ context.Context, client *models.ClientToInspect, _ bool) (*models.InspectedClient, error) {
			if client.Name == "fail-inspect" {
				return nil, errors.New("inspection failed")
			}
			return newInspectedClient(client.Name, "/cfg", "ext"), nil
		},
	}

	p := New(Config{
		Discoverer:  disc,
		Inspector:   insp,
		InspectOnly: true,
	})

	results, err := p.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("expected 1 result (from ok-inspect only), got %d", len(results))
	}
}
