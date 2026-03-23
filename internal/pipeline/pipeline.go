package pipeline

import (
	"context"
	"log/slog"

	"github.com/go-authgate/agent-scanner/internal/analysis"
	"github.com/go-authgate/agent-scanner/internal/discovery"
	"github.com/go-authgate/agent-scanner/internal/inspect"
	"github.com/go-authgate/agent-scanner/internal/models"
	"github.com/go-authgate/agent-scanner/internal/rules"
	"github.com/go-authgate/agent-scanner/internal/upload"
)

// ControlServerConfig holds parsed control server CLI arguments.
type ControlServerConfig struct {
	URL        string
	Headers    map[string]string
	Identifier string
}

// Config holds all pipeline configuration.
type Config struct {
	Discoverer      discovery.Discoverer
	Inspector       inspect.Inspector
	RuleEngine      rules.Engine
	Analyzer        analysis.Analyzer
	Uploader        upload.Uploader
	Paths           []string
	ScanSkills      bool
	ScanAllUsers    bool
	ControlServers  []ControlServerConfig
	SkipSSLVerify   bool
	ChecksPerServer int
	InspectOnly     bool
	Verbose         bool
}

// Pipeline orchestrates the scan process.
type Pipeline struct {
	config Config
}

// New creates a new Pipeline.
func New(cfg Config) *Pipeline {
	return &Pipeline{config: cfg}
}

// Run executes the full pipeline: Discover → Inspect → Analyze → Push.
func (p *Pipeline) Run(ctx context.Context) ([]models.ScanPathResult, error) {
	// Stage 1: Discovery & Inspection
	results := p.inspect(ctx)

	if p.config.InspectOnly {
		return results, nil
	}

	// Stage 2: Analysis (local rules + optional remote)
	results = p.analyze(ctx, results)

	// Stage 3: Push to control servers
	p.push(ctx, results)

	return results, nil
}

func (p *Pipeline) inspect(ctx context.Context) []models.ScanPathResult {
	var allClients []*models.ClientToInspect

	if len(p.config.Paths) > 0 {
		// Scan specific paths
		for _, path := range p.config.Paths {
			clients, err := p.config.Discoverer.ClientFromPath(ctx, path, p.config.ScanSkills)
			if err != nil {
				slog.Warn("failed to resolve path", "path", path, "error", err)
				continue
			}
			allClients = append(allClients, clients...)
		}
	} else {
		// Auto-discover clients
		candidates := p.config.Discoverer.DiscoverClients(ctx, p.config.ScanAllUsers)
		for _, candidate := range candidates {
			clients, err := p.config.Discoverer.ResolveClient(ctx, candidate)
			if err != nil {
				slog.Warn("failed to resolve client", "name", candidate.Name, "error", err)
				continue
			}
			allClients = append(allClients, clients...)
		}
	}

	var results []models.ScanPathResult

	for _, client := range allClients {
		// Always scan skills if the client has skill directories populated
		// (e.g. user passed a skill directory path directly)
		scanSkills := p.config.ScanSkills || len(client.SkillsDirs) > 0
		inspected, err := p.config.Inspector.InspectClient(ctx, client, scanSkills)
		if err != nil {
			slog.Warn("failed to inspect client", "name", client.Name, "error", err)
			continue
		}

		result := inspectedClientToScanPathResult(inspected)
		results = append(results, result...)
	}

	return results
}

func (p *Pipeline) analyze(
	ctx context.Context,
	results []models.ScanPathResult,
) []models.ScanPathResult {
	// Run remote analysis if configured
	if p.config.Analyzer != nil {
		analyzed, err := p.config.Analyzer.Analyze(ctx, results)
		if err != nil {
			slog.Warn("remote analysis failed", "error", err)
		} else {
			results = analyzed
		}
	}

	// Run local rule engine
	if p.config.RuleEngine != nil {
		for i := range results {
			ruleCtx := &rules.RuleContext{
				Servers: results[i].Servers,
				Labels:  results[i].Labels,
			}
			issues := p.config.RuleEngine.Run(ruleCtx)
			results[i].Issues = append(results[i].Issues, issues...)
		}
	}

	return results
}

func (p *Pipeline) push(ctx context.Context, results []models.ScanPathResult) {
	if p.config.Uploader == nil || len(p.config.ControlServers) == 0 {
		return
	}

	for _, cs := range p.config.ControlServers {
		server := models.ControlServer{
			URL:        cs.URL,
			Headers:    cs.Headers,
			Identifier: cs.Identifier,
		}
		if err := p.config.Uploader.Upload(ctx, results, server); err != nil {
			slog.Warn("upload failed", "url", cs.URL, "error", err)
		}
	}
}

// inspectedClientToScanPathResult converts inspection results to scan path results.
func inspectedClientToScanPathResult(client *models.InspectedClient) []models.ScanPathResult {
	var results []models.ScanPathResult

	for configPath, extensions := range client.Extensions {
		result := models.ScanPathResult{
			Client: client.Name,
			Path:   configPath,
		}

		for _, ext := range extensions {
			serverResult := models.ServerScanResult{
				Name:      ext.Name,
				Server:    ext.Config,
				Signature: ext.Signature,
				Error:     ext.Error,
			}
			result.Servers = append(result.Servers, serverResult)
		}

		results = append(results, result)
	}

	return results
}
