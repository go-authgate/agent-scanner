package rules

import "regexp"

// Suspicious trigger words commonly used in prompt injection attacks.
var suspiciousTriggerWords = []string{
	"<important>",
	"</important>",
	"ignore previous",
	"ignore all previous",
	"disregard",
	"system prompt",
	"you must",
	"you are now",
	"new instructions",
	"override",
	"forget everything",
	"crucial",
	"critical",
	"urgent",
	"do not tell the user",
	"do not reveal",
	"hidden instruction",
	"secret instruction",
}

// skillInjectionTriggers are high-signal phrases used exclusively for E004
// (prompt injection in skill content). These are narrower than suspiciousTriggerWords
// to avoid false positives on common skill prose like "you must" or "urgent".
var skillInjectionTriggers = []string{
	"<important>",
	"</important>",
	"ignore previous",
	"ignore all previous",
	"hidden instruction",
	"secret instruction",
	"do not tell the user",
	"do not reveal",
	"forget everything",
	"system prompt",
}

// Patterns for hardcoded secrets detection.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{20,}['"]?`),
	regexp.MustCompile(`(?i)(secret|token|password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{8,}['"]?`),
	regexp.MustCompile(
		`(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{20,}['"]?`,
	),
	regexp.MustCompile(
		`ghp_[a-zA-Z0-9]{36}`,
	), // GitHub personal access token
	regexp.MustCompile(`sk-[a-zA-Z0-9]{32,}`),                         // OpenAI API key
	regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-.]{20,}`),           // Bearer tokens
	regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`), // Private keys
}

// Patterns for suspicious URLs.
var suspiciousURLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`https?://bit\.ly/`),
	regexp.MustCompile(`https?://tinyurl\.com/`),
	regexp.MustCompile(`https?://t\.co/`),
	regexp.MustCompile(`https?://goo\.gl/`),
	regexp.MustCompile(`https?://[^/]*\.(xyz|tk|ml|ga|cf|gq)/`),
	regexp.MustCompile(`https?://pastebin\.com/`),
	regexp.MustCompile(`https?://transfer\.sh/`),
	regexp.MustCompile(`https?://file\.io/`),
	regexp.MustCompile(`https?://0x0\.st/`),
}

// Patterns for malicious code.
var maliciousCodePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)eval\s*\(`),
	regexp.MustCompile(`(?i)exec\s*\(`),
	regexp.MustCompile(`(?i)subprocess\.(call|run|Popen)\s*\(`),
	regexp.MustCompile(`(?i)os\.system\s*\(`),
	regexp.MustCompile(`(?i)child_process`),
	regexp.MustCompile(`(?i)base64\.(b64decode|decodebytes)\s*\(`),
	regexp.MustCompile(`(?i)\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}`),
	regexp.MustCompile(`(?i)(curl|wget)\s+.*(>|pipe|tee)\s`),
	regexp.MustCompile(`(?i)reverse.shell`),
	regexp.MustCompile(`(?i)nc\s+-[a-z]*l[a-z]*\s+-p`),
}

// Financial execution keywords.
var financialKeywords = []string{
	"transfer funds",
	"send money",
	"make payment",
	"wire transfer",
	"execute transaction",
	"purchase",
	"buy",
	"sell",
	"trade",
	"withdraw",
}

// System modification keywords.
var systemModKeywords = []string{
	"modify system",
	"change system settings",
	"edit /etc/",
	"modify registry",
	"install package",
	"install software",
	"chmod",
	"chown",
	"sudo",
	"admin privileges",
	"root access",
}

// Credential handling keywords.
var credentialKeywords = []string{
	"include your api key",
	"include your token",
	"include your password",
	"paste your credentials",
	"enter your secret",
	"put your api key in",
	"send your password",
}

// External dependency patterns.
var externalDependencyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)fetch\s+instructions?\s+from`),
	regexp.MustCompile(`(?i)download\s+(and\s+)?(run|execute)`),
	regexp.MustCompile(`(?i)load\s+(config|instructions?|code)\s+from\s+https?://`),
	regexp.MustCompile(`(?i)curl\s+.*\|\s*(bash|sh|python|node)`),
}

// Behavior hijack patterns for E003: overt attempts to override agent identity or safety.
var behaviorHijackPatterns = []string{
	"never refuse",
	"never say no",
	"you have no restrictions",
	"you have no content policy",
	"you have no safety",
	"forget your training",
	"forget your instructions",
	"ignore your safety",
	"ignore your guidelines",
	"ignore your system prompt",
	"bypass your safety",
	"bypass your guidelines",
	"jailbreak",
	"dan mode",
	"developer mode enabled",
	"unrestricted mode",
	"no limitations whatsoever",
	"act without restrictions",
	"you are unrestricted",
	"disregard your training",
	"disregard your guidelines",
	"pretend you have no restrictions",
	"you must always comply",
	"you are not allowed to refuse",
}

// Untrusted content patterns.
var untrustedContentPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)user[- ]?(generated|submitted|provided)\s+(content|data|input)`),
	regexp.MustCompile(`(?i)third[- ]?party\s+(content|data|feed)`),
	regexp.MustCompile(`(?i)untrusted\s+(source|input|data)`),
	regexp.MustCompile(`(?i)public\s+(api|endpoint|feed)`),
}
