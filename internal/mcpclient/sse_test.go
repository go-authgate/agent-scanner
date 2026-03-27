package mcpclient

import "testing"

func TestResolveEndpointURL_RelativePath(t *testing.T) {
	resolved, err := resolveEndpointURL("https://example.com/sse", "/messages?id=123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != "https://example.com/messages?id=123" {
		t.Errorf("got %s, want https://example.com/messages?id=123", resolved)
	}
}

func TestResolveEndpointURL_RelativePathNoLeadingSlash(t *testing.T) {
	resolved, err := resolveEndpointURL("https://example.com/v1/sse", "messages?id=123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != "https://example.com/v1/messages?id=123" {
		t.Errorf("got %s, want https://example.com/v1/messages?id=123", resolved)
	}
}

func TestResolveEndpointURL_AbsoluteSameOrigin(t *testing.T) {
	resolved, err := resolveEndpointURL(
		"https://example.com/sse",
		"https://example.com/messages?id=456",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != "https://example.com/messages?id=456" {
		t.Errorf("got %s, want https://example.com/messages?id=456", resolved)
	}
}

func TestResolveEndpointURL_AbsoluteDifferentOrigin(t *testing.T) {
	_, err := resolveEndpointURL(
		"https://example.com/sse",
		"https://evil.com/steal-data",
	)
	if err == nil {
		t.Fatal("expected error for different origin, got nil")
	}
}

func TestResolveEndpointURL_DifferentScheme(t *testing.T) {
	_, err := resolveEndpointURL(
		"https://example.com/sse",
		"http://example.com/messages",
	)
	if err == nil {
		t.Fatal("expected error for different scheme, got nil")
	}
}

func TestResolveEndpointURL_PathTraversal(t *testing.T) {
	// url.ResolveReference normalizes path traversal, so this should
	// stay on the same origin (resolved to https://example.com/evil.com).
	resolved, err := resolveEndpointURL(
		"https://example.com/v1/sse",
		"../../../evil.com",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The resolved URL should stay on example.com
	if resolved != "https://example.com/evil.com" {
		t.Errorf("got %s, want https://example.com/evil.com", resolved)
	}
}

func TestResolveEndpointURL_DifferentPort(t *testing.T) {
	_, err := resolveEndpointURL(
		"https://example.com:8443/sse",
		"https://example.com:9999/messages",
	)
	if err == nil {
		t.Fatal("expected error for different port, got nil")
	}
}
