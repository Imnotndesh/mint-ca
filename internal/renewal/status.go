package renewal

import (
	"context"
	"fmt"
	"time"

	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

// Status is the renewal-risk bucket a certificate falls into.
type Status string

const (
	StatusValid        Status = "valid"
	StatusDue          Status = "due"
	StatusExpiringSoon Status = "expiring_soon"
	StatusExpired      Status = "expired"
	StatusRevoked      Status = "revoked"
)

// Classify buckets a certificate's renewal risk given the current time and
// the lead/expiring windows. Revoked and expired statuses take priority over
// the time-based windows; otherwise a cert within expiring of NotAfter is
// "expiring_soon", within lead is "due", and beyond that is "valid".
func Classify(status storage.CertStatus, notAfter, now time.Time, lead, expiring time.Duration) Status {
	if status == storage.CertStatusRevoked {
		return StatusRevoked
	}
	if status == storage.CertStatusExpired || !notAfter.After(now) {
		return StatusExpired
	}
	if !notAfter.After(now.Add(expiring)) {
		return StatusExpiringSoon
	}
	if !notAfter.After(now.Add(lead)) {
		return StatusDue
	}
	return StatusValid
}

// ForEachCert lists every certificate across all active CAs (optionally
// restricted to a single CA when caIDFilter is non-nil), classifies each
// with Classify, and invokes fn. It centralizes the CA/cert scan shared by
// the renewal-status endpoint and the Prometheus exporter's renewal gauges.
func ForEachCert(ctx context.Context, store storage.Store, caIDFilter *uuid.UUID, now time.Time, lead, expiring time.Duration, fn func(cert *storage.Certificate, status Status)) error {
	cas, err := store.ListCAs(ctx)
	if err != nil {
		return fmt.Errorf("renewal: list CAs: %w", err)
	}
	for _, ca := range cas {
		if caIDFilter != nil && ca.ID != *caIDFilter {
			continue
		}
		certs, err := store.ListCertificatesByCA(ctx, ca.ID)
		if err != nil {
			return fmt.Errorf("renewal: list certs for CA %s: %w", ca.ID, err)
		}
		for _, c := range certs {
			fn(c, Classify(c.Status, c.NotAfter, now, lead, expiring))
		}
	}
	return nil
}
