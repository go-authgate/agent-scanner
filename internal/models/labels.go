package models

// ScalarToolLabels are security classification scores for a tool.
type ScalarToolLabels struct {
	IsPublicSink     float64 `json:"is_public_sink"`
	Destructive      float64 `json:"destructive"`
	UntrustedContent float64 `json:"untrusted_content"`
	PrivateData      float64 `json:"private_data"`
}

// ToxicFlowExtraData holds additional data for toxic flow issues.
type ToxicFlowExtraData struct {
	SourceServer string   `json:"source_server"`
	SourceTool   string   `json:"source_tool"`
	SinkServer   string   `json:"sink_server"`
	SinkTool     string   `json:"sink_tool"`
	PrivateTools []string `json:"private_tools,omitempty"`
	FlowType     string   `json:"flow_type"`
}
