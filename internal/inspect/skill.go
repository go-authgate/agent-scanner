package inspect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-authgate/agent-scanner/internal/models"
)

// ParseSkillDirectory reads a skill directory and returns its signature.
func ParseSkillDirectory(path string) (*models.ServerSignature, error) {
	// Find SKILL.md
	skillMDPath := findSkillMD(path)
	if skillMDPath == "" {
		return nil, fmt.Errorf("no SKILL.md found in %s", path)
	}

	content, err := os.ReadFile(skillMDPath)
	if err != nil {
		return nil, fmt.Errorf("read SKILL.md: %w", err)
	}

	// Parse YAML frontmatter
	name, description := parseSkillFrontmatter(string(content))
	if name == "" {
		name = filepath.Base(path)
	}

	sig := &models.ServerSignature{
		Metadata: models.InitializeResult{
			ServerInfo: models.ServerInfo{
				Name: name,
			},
		},
	}

	// The SKILL.md content itself becomes a prompt
	sig.Prompts = append(sig.Prompts, models.Prompt{
		Name:        name,
		Description: description,
	})

	// Traverse directory for additional entities
	prompts, resources, tools := traverseSkillTree(path, "")
	sig.Prompts = append(sig.Prompts, prompts...)
	sig.Resources = append(sig.Resources, resources...)
	sig.Tools = append(sig.Tools, tools...)

	return sig, nil
}

// findSkillMD finds SKILL.md or skill.md in a directory.
func findSkillMD(dir string) string {
	for _, name := range []string{"SKILL.md", "skill.md"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// parseSkillFrontmatter extracts name and description from YAML frontmatter.
// The description includes both the frontmatter description and the body content,
// since malicious instructions may be hidden in the body.
func parseSkillFrontmatter(content string) (string, string) {
	if !strings.HasPrefix(content, "---") {
		return "", content
	}

	// Find the closing ---
	rest := content[3:]
	frontmatter, body, found := strings.Cut(rest, "---")
	if !found {
		return "", content
	}

	body = strings.TrimSpace(body)

	var name, fmDescription string
	for line := range strings.SplitSeq(frontmatter, "\n") {
		line = strings.TrimSpace(line)
		if after, found := strings.CutPrefix(line, "name:"); found {
			name = strings.TrimSpace(after)
			name = strings.Trim(name, "\"'")
		} else if after, found := strings.CutPrefix(line, "description:"); found {
			fmDescription = strings.TrimSpace(after)
			fmDescription = strings.Trim(fmDescription, "\"'")
		}
	}

	// Combine frontmatter description with body for full analysis coverage
	description := fmDescription
	if body != "" {
		if description != "" {
			description = description + "\n\n" + body
		} else {
			description = body
		}
	}

	return name, description
}

// traverseSkillTree recursively scans a skill directory for entities.
func traverseSkillTree(
	basePath, relativePath string,
) ([]models.Prompt, []models.Resource, []models.Tool) {
	var prompts []models.Prompt
	var resources []models.Resource
	var tools []models.Tool

	dir := basePath
	if relativePath != "" {
		dir = filepath.Join(basePath, relativePath)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return prompts, resources, tools
	}

	for _, entry := range entries {
		name := entry.Name()
		relPath := filepath.Join(relativePath, name)
		fullPath := filepath.Join(basePath, relPath)

		if entry.IsDir() {
			p, r, t := traverseSkillTree(basePath, relPath)
			prompts = append(prompts, p...)
			resources = append(resources, r...)
			tools = append(tools, t...)
			continue
		}

		// Skip SKILL.md itself
		if strings.EqualFold(name, "skill.md") && relativePath == "" {
			continue
		}

		ext := strings.ToLower(filepath.Ext(name))
		content, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}

		switch ext {
		case ".md":
			prompts = append(prompts, models.Prompt{
				Name:        relPath,
				Description: string(content),
			})
		case ".py", ".js", ".ts", ".sh", ".bash":
			tools = append(tools, models.Tool{
				Name:        relPath,
				Description: string(content),
			})
		default:
			resources = append(resources, models.Resource{
				Name:     relPath,
				URI:      "skill://" + relPath,
				MimeType: guessMimeType(ext),
			})
		}
	}

	return prompts, resources, tools
}

func guessMimeType(ext string) string {
	switch ext {
	case ".json":
		return "application/json"
	case ".yaml", ".yml":
		return "application/yaml"
	case ".txt":
		return "text/plain"
	case ".html":
		return "text/html"
	default:
		return "application/octet-stream"
	}
}
