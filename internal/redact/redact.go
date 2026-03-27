package redact

import (
	"regexp"
	"strings"

	"github.com/go-authgate/agent-scanner/internal/models"
)

const redactedValue = "**REDACTED**"

var absolutePathPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?:/[a-zA-Z0-9._-]+){3,}`), // Unix paths
	regexp.MustCompile(
		`(?:~[/\\][a-zA-Z0-9._-]+)+`,
	), // Home-relative paths
	regexp.MustCompile(`[A-Z]:[\\\/](?:[a-zA-Z0-9._-]+[\\\/])*[a-zA-Z0-9._-]+`), // Windows paths
}

// AbsolutePaths replaces absolute file paths in text.
func AbsolutePaths(text string) string {
	for _, pattern := range absolutePathPatterns {
		text = pattern.ReplaceAllString(text, redactedValue)
	}
	return text
}

// ServerResult redacts sensitive data from a ServerScanResult.
func ServerResult(result *models.ServerScanResult) {
	switch srv := result.Server.(type) {
	case *models.StdioServer:
		// Redact environment variable values
		for k := range srv.Env {
			srv.Env[k] = redactedValue
		}
		// Redact command arguments that look like paths or secrets
		for i, arg := range srv.Args {
			if isPath(arg) || LooksLikeSecret(arg) {
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
		result.Error.Traceback = AbsolutePaths(result.Error.Traceback)
	}
}

// ScanPathResult redacts all sensitive data in a ScanPathResult.
func ScanPathResult(result *models.ScanPathResult) {
	if result.Error != nil && result.Error.Traceback != "" {
		result.Error.Traceback = AbsolutePaths(result.Error.Traceback)
	}
	for i := range result.Servers {
		ServerResult(&result.Servers[i])
	}
}

func isPath(arg string) bool {
	if len(arg) == 0 {
		return false
	}
	return arg[0] == '/' || arg[0] == '~' ||
		(len(arg) >= 3 && arg[1] == ':' && (arg[2] == '\\' || arg[2] == '/'))
}

// secretPrefixes lists known API key and token prefixes (case-insensitive match).
var secretPrefixes = []string{
	"sk-",             // OpenAI / generic
	"sk-ant-",         // Anthropic
	"ghp_",            // GitHub personal access token
	"gho_",            // GitHub OAuth token
	"github_pat_",     // GitHub fine-grained PAT
	"Bearer ",         // Authorization bearer token
	"AKIA",            // AWS access key ID
	"xoxb-",           // Slack bot token
	"xoxp-",           // Slack user token
	"xapp-",           // Slack app token
	"xoxs-",           // Slack session token
	"glpat-",          // GitLab personal access token
	"npm_",            // npm token
	"pypi-",           // PyPI token
	"whsec_",          // Stripe webhook secret
	"sk_live_",        // Stripe live secret key
	"sk_test_",        // Stripe test secret key
	"rk_live_",        // Stripe restricted key
	"AGE-SECRET-KEY-", // age encryption key
}

// LooksLikeSecret returns true if arg looks like an API key or secret token.
func LooksLikeSecret(arg string) bool {
	lower := strings.ToLower(arg)
	for _, prefix := range secretPrefixes {
		if strings.HasPrefix(lower, strings.ToLower(prefix)) {
			return true
		}
	}

	// High-entropy heuristic: long strings with mixed character classes
	if len(arg) > 20 && !strings.Contains(arg, " ") && looksHighEntropy(arg) {
		return true
	}

	return false
}

// looksHighEntropy returns true if s contains a mix of uppercase, lowercase, and digits.
func looksHighEntropy(s string) bool {
	var hasUpper, hasLower, hasDigit bool
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		}
	}
	return hasUpper && hasLower && hasDigit
}
