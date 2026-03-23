//go:build darwin

package signed

import (
	"log/slog"
	"os/exec"
	"strings"

	"github.com/go-authgate/agent-scanner/internal/models"
)

// Code launcher patterns — interpreters and package managers.
var codeLaunchers = []string{
	"python", "python3", "node", "npm", "npx", "ruby", "php", "perl",
	"java", "bash", "sh", "zsh", "cargo", "uv", "uvx", "mise",
	"docker", "podman", "pipx", "poetry", "pdm", "rye", "bun", "deno",
	"dotnet", "go",
}

// CheckBinarySignature verifies the macOS code signature of a stdio server's binary.
func CheckBinarySignature(server *models.StdioServer) {
	command := server.Command

	// Skip signature check for code launchers (signature doesn't imply code trust)
	baseName := command
	if idx := strings.LastIndex(command, "/"); idx >= 0 {
		baseName = command[idx+1:]
	}
	for _, launcher := range codeLaunchers {
		if strings.HasPrefix(baseName, launcher) {
			return
		}
	}

	// Resolve command path
	path, err := exec.LookPath(command)
	if err != nil {
		return
	}

	// Run codesign verification
	out, err := exec.Command("codesign", "-dvvv", path).CombinedOutput()
	if err != nil {
		slog.Debug("codesign check failed", "command", command, "error", err)
		return
	}

	output := string(out)

	// Check for Apple Root CA in authority chain
	if strings.Contains(output, "Apple Root CA") {
		// Extract identifier
		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(line, "Identifier=") {
				server.BinaryIdentifier = strings.TrimPrefix(line, "Identifier=")
				slog.Debug("binary signed by Apple", "command", command, "identifier", server.BinaryIdentifier)
				return
			}
		}
	} else {
		slog.Warn("binary signed by non-Apple authority", "command", command)
	}
}
