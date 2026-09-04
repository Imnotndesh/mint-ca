package renewal

import (
	"time"

	"mint-ca/internal/storage"
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
