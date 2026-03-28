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
		q.Set(key, redact.RedactedValue)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// sanitizeArgs returns a copy of args with path-like and secret-like values redacted.
func sanitizeArgs(args []string) []string {
	out := make([]string, len(args))
	for i, arg := range args {
		if redact.IsPath(arg) || redact.LooksLikeSecret(arg) {
			out[i] = redact.RedactedValue
		} else {
			out[i] = arg
		}
	}
	return out
}
