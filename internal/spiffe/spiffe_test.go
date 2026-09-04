package spiffe

import "testing"

func TestValidateID_Valid(t *testing.T) {
	cases := []string{
		"spiffe://example.org/ns/default/sa/backend",
		"spiffe://example.org",
		"spiffe://trust.domain.example/path/to/workload",
	}
	for _, id := range cases {
		if _, err := ValidateID(id); err != nil {
			t.Errorf("ValidateID(%q) = %v, want nil", id, err)
		}
	}
}

func TestValidateID_Invalid(t *testing.T) {
	cases := map[string]string{
		"":                                  "empty",
		"https://example.org/foo":           "wrong scheme",
		"spiffe://":                         "missing trust domain",
		"spiffe://Example.org/foo":          "uppercase trust domain",
		"spiffe://user@example.org/foo":     "userinfo",
		"spiffe://example.org/foo?query=1":  "query string",
		"spiffe://example.org/foo#fragment": "fragment",
		"not a url at all \x7f\x00":         "unparseable",
	}
	for id, reason := range cases {
		if _, err := ValidateID(id); err == nil {
			t.Errorf("ValidateID(%q) expected an error (%s), got nil", id, reason)
		}
	}
}

func TestValidateID_TooLong(t *testing.T) {
	long := "spiffe://example.org/"
	for len(long) < 2100 {
		long += "a"
	}
	if _, err := ValidateID(long); err == nil {
		t.Error("expected an error for an over-length SPIFFE ID")
	}
}
