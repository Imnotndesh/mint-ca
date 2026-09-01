package approval

import (
	"testing"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

func rule(prov uuid.UUID, cn, dns []string, maxTTL int64) *storage.CSRAutoApproveRule {
	return &storage.CSRAutoApproveRule{
		ID: uuid.New(), ProvisionerID: prov, Name: "t",
		AllowedCommonNames: cn, AllowedDNS: dns, MaxTTLSeconds: maxTTL, Enabled: true,
	}
}

func TestEvaluate_DisabledRuleNotDecided(t *testing.T) {
	r := rule(uuid.New(), nil, nil, 0)
	r.Enabled = false
	approved, decided, _ := Evaluate(r, Request{ProvisionerID: r.ProvisionerID, CommonName: "x"})
	if decided {
		t.Error("disabled rule must not decide")
	}
	if approved {
		t.Error("disabled rule must not approve")
	}
}

func TestEvaluate_ProvisionerMustMatch(t *testing.T) {
	r := rule(uuid.New(), nil, []string{`\.example\.com$`}, 0)
	approved, decided, _ := Evaluate(r, Request{ProvisionerID: uuid.New(), CommonName: "a", SANsDNS: []string{"a.example.com"}})
	if approved || decided {
		t.Error("rule must not apply to a different provisioner")
	}
}

func TestEvaluate_CommonNameAllowlist(t *testing.T) {
	r := rule(uuid.New(), []string{`^svc-\d+\.example\.com$`}, nil, 0)
	prov := r.ProvisionerID
	if approved, decided, _ := Evaluate(r, Request{ProvisionerID: prov, CommonName: "svc-1.example.com"}); !approved || !decided {
		t.Error("matching CN should approve")
	}
	if approved, _, _ := Evaluate(r, Request{ProvisionerID: prov, CommonName: "other.example.com"}); approved {
		t.Error("non-matching CN must be denied")
	}
}

func TestEvaluate_DNSAllowlist(t *testing.T) {
	r := rule(uuid.New(), nil, []string{`\.internal\.example$`}, 0)
	prov := r.ProvisionerID
	if approved, _, _ := Evaluate(r, Request{ProvisionerID: prov, CommonName: "a", SANsDNS: []string{"host.internal.example"}}); !approved {
		t.Error("matching DNS SAN should approve")
	}
	if approved, _, _ := Evaluate(r, Request{ProvisionerID: prov, CommonName: "a", SANsDNS: []string{"evil.example.com"}}); approved {
		t.Error("non-matching DNS SAN must be denied")
	}
	// Every SAN must match — a mixed set is denied.
	if approved, _, _ := Evaluate(r, Request{ProvisionerID: prov, CommonName: "a", SANsDNS: []string{"ok.internal.example", "bad.example.com"}}); approved {
		t.Error("any non-matching SAN must deny")
	}
}

func TestEvaluate_TTLCap(t *testing.T) {
	r := rule(uuid.New(), nil, nil, 3600)
	prov := r.ProvisionerID
	if approved, _, _ := Evaluate(r, Request{ProvisionerID: prov, CommonName: "a", TTLSeconds: 99999}); approved {
		t.Error("over-TTL must be denied")
	}
	if approved, _, _ := Evaluate(r, Request{ProvisionerID: prov, CommonName: "a", TTLSeconds: 1800}); !approved {
		t.Error("under-TTL should approve")
	}
	// Zero requested TTL uses the default cap.
	big := rule(uuid.New(), nil, nil, 0)
	if approved, _, _ := Evaluate(big, Request{ProvisionerID: big.ProvisionerID, CommonName: "a"}); !approved {
		t.Error("zero-TTL request should approve against default cap")
	}
}
