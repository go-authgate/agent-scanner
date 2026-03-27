package mcpclient

import (
	"net/url"

	"github.com/go-authgate/agent-scanner/internal/redact"
)

// sanitizeURL parses a URL and redacts query parameter values for safe logging.
func sanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if u.RawQuery == "" {
		return rawURL
	}
	q := u.Query()
	for key := range q {
		q.Set(key, "**REDACTED**")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// sanitizeArgs returns a copy of args with path-like and secret-like values redacted.
func sanitizeArgs(args []string) []string {
	out := make([]string, len(args))
	for i, arg := range args {
		if isPath(arg) || redact.LooksLikeSecret(arg) {
			out[i] = "**REDACTED**"
		} else {
			out[i] = arg
		}
	}
	return out
}

// isPath returns true if arg looks like an absolute or home-relative path.
func isPath(arg string) bool {
	if len(arg) == 0 {
		return false
	}
	return arg[0] == '/' || arg[0] == '~' ||
		(len(arg) >= 3 && arg[1] == ':' && (arg[2] == '\\' || arg[2] == '/'))
}
