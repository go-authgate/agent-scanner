package inspect

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/go-authgate/agent-scanner/internal/mcpclient"
	"github.com/go-authgate/agent-scanner/internal/models"
	"golang.org/x/sync/errgroup"
)

// Inspector connects to MCP servers and extracts their signatures.
type Inspector interface {
	InspectServer(
		ctx context.Context,
		name string,
		cfg models.ServerConfig,
	) (*models.InspectedExtension, error)
	InspectSkill(
		ctx context.Context,
		name string,
		cfg *models.SkillServer,
	) (*models.InspectedExtension, error)
	InspectClient(
		ctx context.Context,
		client *models.ClientToInspect,
		scanSkills bool,
	) (*models.InspectedClient, error)
}

type inspector struct {
	client  mcpclient.Client
	timeout int
}

// NewInspector creates a new Inspector.
func NewInspector(client mcpclient.Client, timeout int) Inspector {
	return &inspector{
		client:  client,
		timeout: timeout,
	}
}

func (i *inspector) InspectServer(
	ctx context.Context,
	name string,
	cfg models.ServerConfig,
) (*models.InspectedExtension, error) {
	slog.Debug("inspecting server", "name", name, "type", cfg.GetServerType())

	session, err := i.client.Connect(ctx, cfg, i.timeout)
	if err != nil {
		return &models.InspectedExtension{
			Name:   name,
			Config: cfg,
			Error: models.NewScanError(
				fmt.Sprintf("connect: %v", err),
				models.ErrCatServerStartup,
				true,
			),
		}, nil
	}
	defer session.Close()

	initResult, err := session.Initialize(ctx)
	if err != nil {
		return &models.InspectedExtension{
			Name:   name,
			Config: cfg,
			Error: models.NewScanError(
				fmt.Sprintf("initialize: %v", err),
				models.ErrCatServerStartup,
				true,
			),
		}, nil
	}

	sig := &models.ServerSignature{
		Metadata: *initResult,
	}

	// Fetch tools
	if initResult.Capabilities.Tools != nil {
		tools, err := session.ListTools(ctx)
		if err != nil {
			slog.Warn("failed to list tools", "name", name, "error", err)
		} else {
			sig.Tools = tools
		}
	}

	// Fetch prompts
	if initResult.Capabilities.Prompts != nil {
		prompts, err := session.ListPrompts(ctx)
		if err != nil {
			slog.Warn("failed to list prompts", "name", name, "error", err)
		} else {
			sig.Prompts = prompts
		}
	}

	// Fetch resources
	if initResult.Capabilities.Resources != nil {
		resources, err := session.ListResources(ctx)
		if err != nil {
			slog.Warn("failed to list resources", "name", name, "error", err)
		} else {
			sig.Resources = resources
		}
	}

	slog.Debug("server inspected",
		"name", name,
		"tools", len(sig.Tools),
		"prompts", len(sig.Prompts),
		"resources", len(sig.Resources),
	)

	return &models.InspectedExtension{
		Name:      name,
		Config:    cfg,
		Signature: sig,
	}, nil
}

func (i *inspector) InspectSkill(
	_ context.Context,
	name string,
	cfg *models.SkillServer,
) (*models.InspectedExtension, error) {
	sig, err := ParseSkillDirectory(cfg.Path)
	if err != nil {
		return &models.InspectedExtension{
			Name:   name,
			Config: cfg,
			Error: models.NewScanError(
				fmt.Sprintf("parse skill: %v", err),
				models.ErrCatSkillScan,
				true,
			),
		}, nil
	}

	return &models.InspectedExtension{
		Name:      name,
		Config:    cfg,
		Signature: sig,
	}, nil
}

func (i *inspector) InspectClient(
	ctx context.Context,
	client *models.ClientToInspect,
	scanSkills bool,
) (*models.InspectedClient, error) {
	result := &models.InspectedClient{
		Name:       client.Name,
		ClientPath: client.ClientPath,
		Extensions: make(map[string][]models.InspectedExtension),
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(10) // Concurrent inspection limit

	type extResult struct {
		configPath string
		ext        models.InspectedExtension
	}
	results := make(chan extResult, 100)

	// Inspect MCP servers
	for configPath, configOrErr := range client.MCPConfigs {
		if configOrErr.Error != nil {
			result.Extensions[configPath] = []models.InspectedExtension{{
				Name:  configPath,
				Error: configOrErr.Error,
			}}
			continue
		}

		servers := configOrErr.Config.GetServers()
		for name, serverCfg := range servers {
			name, serverCfg, configPath := name, serverCfg, configPath
			g.Go(func() error {
				ext, _ := i.InspectServer(ctx, name, serverCfg)
				results <- extResult{configPath: configPath, ext: *ext}
				return nil
			})
		}
	}

	// Inspect skills
	if scanSkills {
		for dirPath, entries := range client.SkillsDirs {
			for _, entry := range entries {
				entry, dirPath := entry, dirPath
				g.Go(func() error {
					ext, _ := i.InspectSkill(ctx, entry.Name, entry.Server)
					results <- extResult{configPath: dirPath, ext: *ext}
					return nil
				})
			}
		}
	}

	// Collect results
	go func() {
		_ = g.Wait()
		close(results)
	}()

	for r := range results {
		result.Extensions[r.configPath] = append(result.Extensions[r.configPath], r.ext)
	}

	return result, nil
}
