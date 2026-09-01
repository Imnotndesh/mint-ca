package setup

import (
	"strings"
	"testing"
)

func TestDefaultTermsURL(t *testing.T) {
	if got := DefaultTermsURL("https://ca.example.com"); got != "https://ca.example.com"+TermsPath {
		t.Errorf("DefaultTermsURL = %q", got)
	}
	// A base with a trailing slash yields a harmless double slash; both are
	// valid URLs, we only require it to reference the terms path.
	got := DefaultTermsURL("https://ca.example.com/")
	if !strings.Contains(got, TermsPath) {
		t.Errorf("DefaultTermsURL with trailing slash = %q", got)
	}
}

func TestTermsURL_RequiresValidBase(t *testing.T) {
	if got := TermsURL(""); got != "" {
		t.Errorf("TermsURL(\"\") = %q, want empty", got)
	}
	if got := TermsURL("not-a-url"); got != "" {
		t.Errorf("TermsURL(relative) = %q, want empty", got)
	}
	if got := TermsURL("https://ca.example.com"); got == "" {
		t.Error("TermsURL(valid) should be non-empty")
	}
}

func TestDefaultTermsText_Content(t *testing.T) {
	lower := strings.ToLower(DefaultTermsText)
	for _, want := range []string{
		"terms of service",
		"no warranty",
		"limitation of liability",
		"as is",
		"revok",
	} {
		if !strings.Contains(lower, want) {
			t.Errorf("DefaultTermsText missing expected phrase %q", want)
		}
	}
	if len(DefaultTermsText) < 500 {
		t.Errorf("DefaultTermsText suspiciously short: %d bytes", len(DefaultTermsText))
	}
}
