package policy

import (
	"net"
	"testing"

	"mint-ca/internal/storage"
)

func profReq(keyAlgo string, ttl int64, sansDNS []string, sansIP []net.IP, sansEmail []string) CertRequest {
	return CertRequest{KeyAlgo: keyAlgo, TTLSeconds: ttl, SANsDNS: sansDNS, SANsIP: sansIP, SANsEmail: sansEmail}
}

// An empty profile imposes no constraints.
func TestEvaluateProfile_EmptyProfileAllowsEverything(t *testing.T) {
	if err := EvaluateProfile(&storage.Profile{}, profReq("rsa-2048", 864000, nil, nil, nil)); err != nil {
		t.Errorf("empty profile should allow, got: %v", err)
	}
}

// Key algorithm restriction.
func TestEvaluateProfile_KeyAlgoRestricted(t *testing.T) {
	prof := &storage.Profile{AllowedKeyAlgos: []string{"ecdsa-p256", "rsa-2048"}}
	if err := EvaluateProfile(prof, profReq("ed25519", 3600, nil, nil, nil)); err == nil {
		t.Error("expected disallowed key algo to be rejected")
	}
	if err := EvaluateProfile(prof, profReq("ecdsa-p256", 3600, nil, nil, nil)); err != nil {
		t.Errorf("expected allowed key algo, got: %v", err)
	}
}

// TTL cap.
func TestEvaluateProfile_TTLCap(t *testing.T) {
	prof := &storage.Profile{MaxTTLSeconds: 3600 * 24} // 1 day
	if err := EvaluateProfile(prof, profReq("", 3600*48, nil, nil, nil)); err == nil {
		t.Error("expected over-TTL to be rejected")
	}
	if err := EvaluateProfile(prof, profReq("", 3600*12, nil, nil, nil)); err != nil {
		t.Errorf("expected under-TTL allowed, got: %v", err)
	}
}

// RequireSAN.
func TestEvaluateProfile_RequireSAN(t *testing.T) {
	prof := &storage.Profile{RequireSAN: true}
	if err := EvaluateProfile(prof, profReq("", 3600, nil, nil, nil)); err == nil {
		t.Error("expected missing SAN to be rejected when RequireSAN")
	}
	if err := EvaluateProfile(prof, profReq("", 3600, []string{"host.example.com"}, nil, nil)); err != nil {
		t.Errorf("expected SAN present to pass, got: %v", err)
	}
}

// Wildcard restriction: strict by default; only allowed when AllowWildcard=true.
func TestEvaluateProfile_WildcardDisallowed(t *testing.T) {
	// Default profile rejects wildcard SANs.
	if err := EvaluateProfile(&storage.Profile{}, profReq("", 3600, []string{"*.example.com"}, nil, nil)); err == nil {
		t.Error("expected wildcard SAN rejected by default profile")
	}
	// AllowWildcard=true permits a wildcard SAN.
	if err := EvaluateProfile(&storage.Profile{AllowWildcard: true}, profReq("", 3600, []string{"*.example.com"}, nil, nil)); err != nil {
		t.Errorf("expected wildcard allowed when AllowWildcard=true, got: %v", err)
	}
	// AllowWildcard does NOT affect non-wildcard SANs.
	if err := EvaluateProfile(&storage.Profile{}, profReq("", 3600, []string{"host.example.com"}, nil, nil)); err != nil {
		t.Errorf("non-wildcard SAN should pass, got: %v", err)
	}
}
