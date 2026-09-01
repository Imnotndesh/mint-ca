package policy

import (
	"strings"
	"testing"
)

// TestEvaluateSSH_UnconstrainedPermitsEverything with an empty body applies
// engine defaults and echoes the requested principals unchanged.
func TestEvaluateSSH_Unconstrained(t *testing.T) {
	d, err := EvaluateSSH(&SSHPolicyBody{}, SSHCertRequest{
		CertType:   "user",
		KeyAlgo:    "ssh-ed25519",
		Principals: []string{"alice", "bob"},
		TTLSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(d.Principals) != 2 || d.Principals[0] != "alice" {
		t.Errorf("principals = %v", d.Principals)
	}
	if d.TTLSeconds != 3600 {
		t.Errorf("TTL = %d, want 3600", d.TTLSeconds)
	}
	if d.CriticalOptions == nil {
		t.Errorf("expected empty (non-nil) critical options map")
	}
}

func TestEvaluateSSH_DefaultTTLAppliedWhenZero(t *testing.T) {
	// No explicit TTL and no body default -> user default of 8h.
	d, err := EvaluateSSH(&SSHPolicyBody{}, SSHCertRequest{CertType: "user", Principals: []string{"u"}})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if d.TTLSeconds != defaultUserTTL {
		t.Errorf("default user TTL = %d, want %d", d.TTLSeconds, defaultUserTTL)
	}

	// Host cert default of 1y.
	d2, _ := EvaluateSSH(&SSHPolicyBody{}, SSHCertRequest{CertType: "host", Principals: []string{"h"}})
	if d2.TTLSeconds != defaultHostTTL {
		t.Errorf("default host TTL = %d, want %d", d2.TTLSeconds, defaultHostTTL)
	}

	// Body default overrides when request TTL is zero.
	d3, _ := EvaluateSSH(&SSHPolicyBody{DefaultTTLSeconds: 7200}, SSHCertRequest{CertType: "user", Principals: []string{"u"}})
	if d3.TTLSeconds != 7200 {
		t.Errorf("body default TTL = %d, want 7200", d3.TTLSeconds)
	}
}

func TestEvaluateSSH_TTLClampsToMax(t *testing.T) {
	body := &SSHPolicyBody{MaxTTLSeconds: 3600}
	d, err := EvaluateSSH(body, SSHCertRequest{CertType: "user", Principals: []string{"u"}, TTLSeconds: 86400})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if d.TTLSeconds != 3600 {
		t.Errorf("TTL = %d, want clamped 3600", d.TTLSeconds)
	}
}

func TestEvaluateSSH_TTLRaisesToMin(t *testing.T) {
	body := &SSHPolicyBody{MinTTLSeconds: 3600}
	d, err := EvaluateSSH(body, SSHCertRequest{CertType: "user", Principals: []string{"u"}, TTLSeconds: 60})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if d.TTLSeconds != 3600 {
		t.Errorf("TTL = %d, want raised 3600", d.TTLSeconds)
	}
}

func TestEvaluateSSH_KeyAlgoAllowlist(t *testing.T) {
	body := &SSHPolicyBody{KeyAlgoAllowlist: []string{"ssh-ed25519"}}
	if _, err := EvaluateSSH(body, SSHCertRequest{Principals: []string{"u"}, KeyAlgo: "ssh-ed25519"}); err != nil {
		t.Errorf("ed25519 should be allowed: %v", err)
	}
	if _, err := EvaluateSSH(body, SSHCertRequest{Principals: []string{"u"}, KeyAlgo: "ssh-rsa"}); err == nil {
		t.Error("ssh-rsa should be denied when only ed25519 allowed")
	}
	// Unknown/empty key algo passes when allowance list configured (cannot verify).
	if _, err := EvaluateSSH(body, SSHCertRequest{Principals: []string{"u"}, KeyAlgo: ""}); err != nil {
		t.Errorf("empty key algo should be allowed: %v", err)
	}
}

func TestEvaluateSSH_RequiresPrincipal(t *testing.T) {
	if _, err := EvaluateSSH(&SSHPolicyBody{}, SSHCertRequest{Principals: nil}); err == nil {
		t.Error("expected error when no principals given")
	}
}

func TestEvaluateSSH_PrincipalDenylist(t *testing.T) {
	body := &SSHPolicyBody{PrincipalDenylist: []string{"root", "admin"}}
	if _, err := EvaluateSSH(body, SSHCertRequest{Principals: []string{"alice", "root"}}); err == nil {
		t.Error("expected denial for principal on denylist")
	}
	d, err := EvaluateSSH(body, SSHCertRequest{Principals: []string{"alice", "bob"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(d.Principals) != 2 {
		t.Errorf("principals = %v", d.Principals)
	}
}

func TestEvaluateSSH_PrincipalAllowlist(t *testing.T) {
	body := &SSHPolicyBody{PrincipalAllowlist: []string{"dev-*", "ops.example.com"}}
	if _, err := EvaluateSSH(body, SSHCertRequest{Principals: []string{"dev-cicd"}}); err != nil {
		t.Errorf("dev-cicd should match dev-* allowlist: %v", err)
	}
	if _, err := EvaluateSSH(body, SSHCertRequest{Principals: []string{"ops.example.com"}}); err != nil {
		t.Errorf("ops.example.com should match allowlist: %v", err)
	}
	if _, err := EvaluateSSH(body, SSHCertRequest{Principals: []string{"unknown"}}); err == nil {
		t.Error("unknown principal should be denied when allowlist present")
	}
}

func TestEvaluateSSH_CriticalOptionAllowlist(t *testing.T) {
	body := &SSHPolicyBody{CriticalOptionAllowlist: []string{"force-command"}}
	if _, err := EvaluateSSH(body, SSHCertRequest{
		Principals:      []string{"u"},
		CriticalOptions: map[string]string{"source-address": "10.0.0.0/8"},
	}); err == nil {
		t.Error("source-address should be denied when only force-command allowed")
	}
	d, err := EvaluateSSH(body, SSHCertRequest{
		Principals:      []string{"u"},
		CriticalOptions: map[string]string{"force-command": "/bin/true"},
	})
	if err != nil {
		t.Fatalf("force-command should be allowed: %v", err)
	}
	if d.CriticalOptions["force-command"] != "/bin/true" {
		t.Errorf("critical option value lost: %v", d.CriticalOptions)
	}
}

func TestEvaluateSSH_DefaultCriticalOptionsInjected(t *testing.T) {
	body := &SSHPolicyBody{
		CriticalOptionAllowlist: []string{"source-address"},
		DefaultCriticalOptions:  map[string]string{"source-address": "10.0.0.0/8"},
	}
	d, err := EvaluateSSH(body, SSHCertRequest{Principals: []string{"u"}})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if d.CriticalOptions["source-address"] != "10.0.0.0/8" {
		t.Errorf("default critical option not injected: %v", d.CriticalOptions)
	}
}

func TestEvaluateSSH_ExtensionAllowlistWithDefaults(t *testing.T) {
	// When an extension allowlist is present but the default permit-* set is
	// not in it, the engine must still inject the OpenSSH defaults for user
	// certs (interactive usability) but keep the allowlist-only extensions.
	body := &SSHPolicyBody{ExtensionAllowlist: []string{"permit-pty", "custom-opt"}}
	d, err := EvaluateSSH(body, SSHCertRequest{CertType: "user", Principals: []string{"u"}})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if _, ok := d.Extensions["permit-pty"]; !ok {
		t.Error("permit-pty should be present (in allowlist + default set)")
	}
	if _, ok := d.Extensions["permit-user-rc"]; !ok {
		t.Error("permit-user-rc is an OpenSSH default and should still be injected")
	}
}

func TestEvaluateSSH_ExtensionAllowlistDeniesOffList(t *testing.T) {
	body := &SSHPolicyBody{ExtensionAllowlist: []string{"permit-pty"}}
	if _, err := EvaluateSSH(body, SSHCertRequest{
		Principals: []string{"u"},
		Extensions: map[string]string{"custom-opt": "x"},
	}); err == nil {
		t.Error("custom-opt should be denied when not on allowlist")
	}
}

func TestEvaluateSSH_DefaultSSHExtensionsInjectedForUser(t *testing.T) {
	d, _ := EvaluateSSH(&SSHPolicyBody{}, SSHCertRequest{CertType: "user", Principals: []string{"u"}})
	for k := range defaultSSHExtensions {
		if _, ok := d.Extensions[k]; !ok {
			t.Errorf("default extension %q missing for user cert", k)
		}
	}
	// Host certs carry no default extensions.
	dh, _ := EvaluateSSH(&SSHPolicyBody{}, SSHCertRequest{CertType: "host", Principals: []string{"h"}})
	if len(dh.Extensions) != 0 {
		t.Errorf("host cert should have no extensions, got %v", dh.Extensions)
	}
}

func TestMatchName(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"ops.example.com", "ops.example.com", true},
		{"ops.example.com", "other.example.com", false},
		{"dev-*", "dev-cicd", true},
		{"dev-*", "qa", false},
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "example.com", false},
		{"*", "anything.at.all", true},
	}
	for _, c := range cases {
		if got := matchName(c.pattern, c.name); got != c.want {
			t.Errorf("matchName(%q,%q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestSortPrincipals(t *testing.T) {
	in := []string{"bob", "alice"}
	out := SortPrincipals(in)
	if out[0] != "alice" || out[1] != "bob" {
		t.Errorf("SortPrincipals = %v", out)
	}
	if strings.Join(in, ",") != "bob,alice" {
		t.Errorf("SortPrincipals mutated input: %v", in)
	}
}
