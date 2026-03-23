package models

// ControlServer represents a control server for uploading scan results.
type ControlServer struct {
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers,omitempty"`
	Identifier string            `json:"identifier"`
}

// ScanUserInfo holds user/host information for scan uploads.
type ScanUserInfo struct {
	Hostname string `json:"hostname"`
	Username string `json:"username"`
}

// ScanMetadata holds metadata about the scan.
type ScanMetadata struct {
	Version     string `json:"version,omitempty"`
	Environment string `json:"environment,omitempty"`
}

// ScanPathResultsCreate is the payload for uploading scan results.
type ScanPathResultsCreate struct {
	ScanPathResults []ScanPathResult `json:"scan_path_results"`
	ScanUserInfo    ScanUserInfo     `json:"scan_user_info"`
	ScanMetadata    *ScanMetadata    `json:"scan_metadata,omitempty"`
}
