package version

// Build-time variables injected via ldflags.
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
	GoVersion = "unknown"
	BuildOS   = "unknown"
	BuildArch = "unknown"
)
