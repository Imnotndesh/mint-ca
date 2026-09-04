package renewal

import (
	"testing"
	"time"

	"mint-ca/internal/storage"
)

func TestClassify(t *testing.T) {
	now := time.Now().UTC()
	lead := 7 * 24 * time.Hour
	expiring := 48 * time.Hour

	cases := []struct {
		name     string
		status   storage.CertStatus
		notAfter time.Time
		want     Status
	}{
		{"revoked takes priority", storage.CertStatusRevoked, now.Add(24 * time.Hour), StatusRevoked},
		{"already expired", storage.CertStatusActive, now.Add(-time.Hour), StatusExpired},
		{"expired status set", storage.CertStatusExpired, now.Add(time.Hour), StatusExpired},
		{"within expiring window", storage.CertStatusActive, now.Add(24 * time.Hour), StatusExpiringSoon},
		{"exactly at expiring boundary", storage.CertStatusActive, now.Add(expiring), StatusExpiringSoon},
		{"within lead window but past expiring", storage.CertStatusActive, now.Add(5 * 24 * time.Hour), StatusDue},
		{"exactly at lead boundary", storage.CertStatusActive, now.Add(lead), StatusDue},
		{"well beyond lead window", storage.CertStatusActive, now.Add(30 * 24 * time.Hour), StatusValid},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Classify(c.status, c.notAfter, now, lead, expiring)
			if got != c.want {
				t.Errorf("Classify(%v, %v) = %v, want %v", c.status, c.notAfter, got, c.want)
			}
		})
	}
}
