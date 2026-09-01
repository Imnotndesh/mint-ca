package revocation

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	mintcrypto "mint-ca/internal/crypto"

	"golang.org/x/crypto/ocsp"
)

// ocspRequestWithNonce builds a DER OCSP request for the issuer, targeting that
// issuer's serial number, with a raw nonce stored in the OCSP nonce extension.
//
// golang.org/x/crypto/ocsp doesn't expose a way to set request extensions, so we
// build a request with ocsp.CreateRequest, parse it back as raw ASN.1, inject the
// nonce extension (Value holds the raw nonce bytes — exactly how the extnValue
// OCTET STRING is unwrapped on the wire), and re-marshal.
func ocspRequestWithNonce(t *testing.T, issuer *x509.Certificate, nonce []byte) []byte {
	t.Helper()
	base, err := ocsp.CreateRequest(issuer, issuer, nil)
	if err != nil {
		t.Fatalf("base request: %v", err)
	}
	var outer struct {
		TBSRequest struct {
			Version       int             `asn1:"optional,explicit,tag:0,default:0"`
			RequestList   []asn1.RawValue
			Extensions    []pkix.Extension `asn1:"optional,explicit,tag:2"`
		}
	}
	if _, err := asn1.Unmarshal(base, &outer); err != nil {
		t.Fatalf("unmarshal base: %v", err)
	}
	outer.TBSRequest.Extensions = []pkix.Extension{
		{Id: idPkixOcspNonce, Value: nonce},
	}
	out, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatalf("marshal with nonce: %v", err)
	}
	return out
}

func TestExtractOCSPNonce_PresentAndAbsent(t *testing.T) {
	ctx := context.Background()
	store := newTestFakeStore()
	ks, _ := mintcrypto.NewKeystore(make([]byte, 32))
	caRec, _ := newTestCA(t, ks)
	store.cas[caRec.ID] = caRec

	responder := NewOCSPResponder(store, ks)

	issuer := parseCertPEMForTest(t, caRec.CertPEM)
	reqDER := ocspRequestWithNonce(t, issuer, []byte("abc123nonce"))

	respDER := responder.Respond(ctx, caRec.ID, reqDER)
	if len(respDER) == 0 || isInternalError(respDER) {
		t.Fatalf("responder returned an error response")
	}
	parsed, err := ocsp.ParseResponse(respDER, nil)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}

	found := false
	for _, ext := range parsed.Extensions {
		if ext.Id.Equal(idPkixOcspNonce) {
			found = true
			if string(ext.Value) != "abc123nonce" {
				t.Errorf("nonce mismatch: got %q want %q", ext.Value, "abc123nonce")
			}
		}
	}
	if !found {
		t.Error("expected nonce extension echoed in OCSP response")
	}
}

func TestOCSPResponse_NoNonceWhenNotRequested(t *testing.T) {
	ctx := context.Background()
	store := newTestFakeStore()
	ks, _ := mintcrypto.NewKeystore(make([]byte, 32))
	caRec, _ := newTestCA(t, ks)
	store.cas[caRec.ID] = caRec

	responder := NewOCSPResponder(store, ks)

	issuer := parseCertPEMForTest(t, caRec.CertPEM)
	reqDER, err := ocsp.CreateRequest(issuer, issuer, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	respDER := responder.Respond(ctx, caRec.ID, reqDER)
	if len(respDER) == 0 || isInternalError(respDER) {
		t.Fatalf("responder returned an error response")
	}
	parsed, err := ocsp.ParseResponse(respDER, nil)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	for _, ext := range parsed.Extensions {
		if ext.Id.Equal(idPkixOcspNonce) {
			t.Error("did not expect nonce extension when request carried none")
		}
	}
}

func TestExtractOCSPNonce_TooLargeIsCapped(t *testing.T) {
	ctx := context.Background()
	store := newTestFakeStore()
	ks, _ := mintcrypto.NewKeystore(make([]byte, 32))
	caRec, _ := newTestCA(t, ks)
	store.cas[caRec.ID] = caRec

	responder := NewOCSPResponder(store, ks)

	issuer := parseCertPEMForTest(t, caRec.CertPEM)
	bigNonce := make([]byte, 64)
	for i := range bigNonce {
		bigNonce[i] = byte(i)
	}
	reqDER := ocspRequestWithNonce(t, issuer, bigNonce)

	respDER := responder.Respond(ctx, caRec.ID, reqDER)
	parsed, err := ocsp.ParseResponse(respDER, nil)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	for _, ext := range parsed.Extensions {
		if ext.Id.Equal(idPkixOcspNonce) {
			if len(ext.Value) != maxOCSPNonceSize {
				t.Errorf("nonce cap: got %d bytes want %d", len(ext.Value), maxOCSPNonceSize)
			}
		}
	}
}

// isInternalError detects the pre-built DER blob Respond() returns on failure.
func isInternalError(der []byte) bool {
	return string(der) == string(ocsp.InternalErrorErrorResponse)
}

func parseCertPEMForTest(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	cert, err := parseCertPEM([]byte(certPEM))
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}
