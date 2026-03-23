package discovery

import (
	"strings"

	"github.com/go-authgate/agent-scanner/internal/models"
)

// Supported direct scan URI prefixes.
var supportedSchemes = []string{
	"streamable-https://",
	"streamable-http://",
	"sse://",
	"npm:",
	"pypi:",
	"oci://",
}

// IsDirectScan returns true if the path is a direct scan URI.
func IsDirectScan(path string) bool {
	for _, scheme := range supportedSchemes {
		if strings.HasPrefix(path, scheme) {
			return true
		}
	}
	return false
}

// DirectScanToServerConfig converts a direct scan URI to a server config.
func DirectScanToServerConfig(path string) (string, models.ServerConfig) {
	switch {
	case strings.HasPrefix(path, "streamable-https://"):
		url := "https://" + strings.TrimPrefix(path, "streamable-https://")
		return url, &models.RemoteServer{URL: url, Type: models.ServerTypeHTTP}

	case strings.HasPrefix(path, "streamable-http://"):
		url := "http://" + strings.TrimPrefix(path, "streamable-http://")
		return url, &models.RemoteServer{URL: url, Type: models.ServerTypeHTTP}

	case strings.HasPrefix(path, "sse://"):
		url := "https://" + strings.TrimPrefix(path, "sse://")
		return url, &models.RemoteServer{URL: url, Type: models.ServerTypeSSE}

	case strings.HasPrefix(path, "npm:"):
		pkg := strings.TrimPrefix(path, "npm:")
		name, version := parsePackageNameVersion(pkg)
		arg := name
		if version != "" {
			arg = name + "@" + version
		}
		return name, &models.StdioServer{
			Command: "npx",
			Args:    []string{"-y", arg},
		}

	case strings.HasPrefix(path, "pypi:"):
		pkg := strings.TrimPrefix(path, "pypi:")
		name, version := parsePackageNameVersion(pkg)
		arg := name
		if version != "" {
			arg = name + "@" + version
		}
		return name, &models.StdioServer{
			Command: "uvx",
			Args:    []string{arg},
		}

	case strings.HasPrefix(path, "oci://"):
		image := strings.TrimPrefix(path, "oci://")
		return image, &models.StdioServer{
			Command: "docker",
			Args:    []string{"run", "-i", "--rm", image},
		}
	}

	return "", nil
}

// parsePackageNameVersion splits "name@version" into (name, version).
func parsePackageNameVersion(pkg string) (string, string) {
	// Handle scoped packages like @scope/name@version
	idx := strings.LastIndex(pkg, "@")
	if idx <= 0 {
		return pkg, ""
	}
	// Check if the @ is part of a scope
	if pkg[0] == '@' && strings.Count(pkg, "@") == 1 {
		return pkg, ""
	}
	return pkg[:idx], pkg[idx+1:]
}
