package redact

import (
	"regexp"
	"strings"

	"github.com/go-authgate/agent-scanner/internal/models"
)

const redactedValue = "**REDACTED**"

var absolutePathPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?:/[a-zA-Z0-9._-]+){3,}`),                   // Unix paths
	regexp.MustCompile(`(?:~[/\\][a-zA-Z0-9._-]+)+`),                 // Home-relative paths
	regexp.MustCompile(`[A-Z]:[\\\/](?:[a-zA-Z0-9._-]+[\\\/])*[a-zA-Z0-9._-]+`), // Windows paths
}

// RedactAbsolutePaths replaces absolute file paths in text.
func RedactAbsolutePaths(text string) string {
	for _, pattern := range absolutePathPatterns {
		text = pattern.ReplaceAllString(text, redactedValue)
	}
	return text
}

// RedactServerResult redacts sensitive data from a ServerScanResult.
func RedactServerResult(result *models.ServerScanResult) {
	switch srv := result.Server.(type) {
	case *models.StdioServer:
		// Redact environment variable values
		for k := range srv.Env {
			srv.Env[k] = redactedValue
		}
		// Redact command arguments that look like paths or secrets
		for i, arg := range srv.Args {
			if isPath(arg) || looksLikeSecret(arg) {
				srv.Args[i] = redactedValue
			}
		}
	case *models.RemoteServer:
		// Redact header values
		for k := range srv.Headers {
			srv.Headers[k] = redactedValue
		}
		// Redact URL query parameters
		if idx := strings.IndexByte(srv.URL, '?'); idx >= 0 {
			srv.URL = srv.URL[:idx] + "?" + redactedValue
		}
	}

	// Redact traceback paths
	if result.Error != nil && result.Error.Traceback != "" {
		result.Error.Traceback = RedactAbsolutePaths(result.Error.Traceback)
	}
}

// RedactScanPathResult redacts all sensitive data in a ScanPathResult.
func RedactScanPathResult(result *models.ScanPathResult) {
	if result.Error != nil && result.Error.Traceback != "" {
		result.Error.Traceback = RedactAbsolutePaths(result.Error.Traceback)
	}
	for i := range result.Servers {
		RedactServerResult(&result.Servers[i])
	}
}

func isPath(arg string) bool {
	if len(arg) == 0 {
		return false
	}
	return arg[0] == '/' || arg[0] == '~' ||
		(len(arg) >= 3 && arg[1] == ':' && (arg[2] == '\\' || arg[2] == '/'))
}

func looksLikeSecret(arg string) bool {
	lower := strings.ToLower(arg)
	for _, prefix := range []string{"sk-", "ghp_", "gho_", "github_pat_", "Bearer "} {
		if strings.HasPrefix(lower, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}
