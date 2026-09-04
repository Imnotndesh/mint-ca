package handlers

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestIssue_WithSpiffeID_EmbedsURISAN(t *testing.T) {
	_, _, r, caID := setupEventsHandler(t)
	provID := uuid.New()

	body, _ := json.Marshal(map[string]any{
		"ca_id":          caID.String(),
		"provisioner_id": provID.String(),
		"common_name":    "backend.example.org",
		"ttl_seconds":    3600,
		"spiffe_id":      "spiffe://example.org/ns/default/sa/backend",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/issue", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		CertPEM string `json:"cert_pem"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	block, _ := pem.Decode([]byte(resp.CertPEM))
	if block == nil {
		t.Fatal("no PEM block in cert_pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://example.org/ns/default/sa/backend" {
		t.Errorf("expected the SPIFFE ID as a URI SAN, got %+v", cert.URIs)
	}
}

func TestIssue_WithInvalidSpiffeID_Rejected(t *testing.T) {
	_, _, r, caID := setupEventsHandler(t)
	provID := uuid.New()

	body, _ := json.Marshal(map[string]any{
		"ca_id":          caID.String(),
		"provisioner_id": provID.String(),
		"common_name":    "backend.example.org",
		"ttl_seconds":    3600,
		"spiffe_id":      "https://not-spiffe.example.org/foo",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/issue", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s, want 400", rec.Code, rec.Body.String())
	}
}
