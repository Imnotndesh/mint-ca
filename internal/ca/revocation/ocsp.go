package revocation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"sync"
	"time"

	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/storage"

	"github.com/google/uuid"
	"golang.org/x/crypto/ocsp"
)

// OCSPResponder handles OCSP requests for certificates issued by mint-ca CAs.
type delegatedCache struct {
	cert    *x509.Certificate
	key     crypto.Signer
	expires time.Time
}

type OCSPResponder struct {
	store    storage.Store
	keystore *mintcrypto.Keystore
	mu       sync.RWMutex
	// delegates caches the delegate created at generateDelegatedSigner() in memory
	delegates map[string]*delegatedCache
}

// NewOCSPResponder constructs an OCSPResponder.
func NewOCSPResponder(store storage.Store, keystore *mintcrypto.Keystore) *OCSPResponder {
	return &OCSPResponder{store: store, keystore: keystore}
}

// Respond parses a raw DER-encoded OCSP request body and returns a signed DER-encoded OCSP response.
func (r *OCSPResponder) Respond(ctx context.Context, caID uuid.UUID, requestDER []byte) []byte {
	resp, err := r.respond(ctx, caID, requestDER)
	if err != nil {
		// Return a standards-compliant OCSP error response.
		// ocsp.InternalErrorErrorResponse is a pre-built DER blob defined
		// in golang.org/x/crypto/ocsp for exactly this situation.
		return ocsp.InternalErrorErrorResponse
	}
	return resp
}

// respond is the internal implementation that can return a Go error.Respond() wraps it and converts errors to OCSP error responses.
func (r *OCSPResponder) respond(ctx context.Context, caID uuid.UUID, requestDER []byte) ([]byte, error) {
	req, err := ocsp.ParseRequest(requestDER)
	if err != nil {
		return nil, fmt.Errorf("ocsp: parse request: %w", err)
	}
	caRecord, err := r.store.GetCA(ctx, caID)
	if err != nil {
		return nil, fmt.Errorf("ocsp: load CA: %w", err)
	}
	if caRecord == nil {
		return nil, fmt.Errorf("ocsp: CA %s not found", caID)
	}

	caCert, err := parseCertPEM([]byte(caRecord.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("ocsp: parse CA cert: %w", err)
	}

	caKey, err := r.loadKey(caRecord)
	if err != nil {
		return nil, fmt.Errorf("ocsp: load CA key: %w", err)
	}

	serial := req.SerialNumber.String()
	cert, err := r.store.GetCertificateBySerial(ctx, serial)
	if err != nil {
		return nil, fmt.Errorf("ocsp: look up serial %s: %w", serial, err)
	}

	now := time.Now().UTC()
	thisUpdate := now.Add(-5 * time.Minute)
	nextUpdate := now.Add(1 * time.Hour)

	var template ocsp.Response
	switch {
	case cert == nil:
		template = ocsp.Response{
			Status:     ocsp.Unknown,
			ThisUpdate: thisUpdate,
			NextUpdate: nextUpdate,
		}

	case cert.Status == storage.CertStatusRevoked:
		revokedAt := now
		if cert.RevokedAt != nil {
			revokedAt = cert.RevokedAt.UTC()
		}
		reason := ocsp.Unspecified
		if cert.RevokeReason != nil {
			reason = *cert.RevokeReason
		}
		nextUpdate = now.Add(24 * time.Hour)

		template = ocsp.Response{
			Status:           ocsp.Revoked,
			SerialNumber:     req.SerialNumber,
			ThisUpdate:       thisUpdate,
			NextUpdate:       nextUpdate,
			RevokedAt:        revokedAt,
			RevocationReason: reason,
		}

	default:
		template = ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: req.SerialNumber,
			ThisUpdate:   thisUpdate,
			NextUpdate:   nextUpdate,
		}
	}
	r.mu.Lock()
	if r.delegates == nil {
		r.delegates = make(map[string]*delegatedCache)
	}

	delegate, exists := r.delegates[caRecord.ID.String()]
	if !exists || time.Now().Add(24*time.Hour).After(delegate.expires) {
		dCert, dKey, err := r.generateDelegatedSigner(caCert, caKey)
		if err != nil {
			r.mu.Unlock()
			return nil, fmt.Errorf("ocsp: generate delegated signer: %w", err)
		}
		delegate = &delegatedCache{
			cert:    dCert,
			key:     dKey,
			expires: dCert.NotAfter,
		}
		r.delegates[caRecord.ID.String()] = delegate
	}
	r.mu.Unlock()
	template.Certificate = delegate.cert
	responseDER, err := ocsp.CreateResponse(caCert, delegate.cert, template, delegate.key)
	if err != nil {
		return nil, fmt.Errorf("ocsp: create response: %w", err)
	}

	return responseDER, nil
}

func (r *OCSPResponder) loadKey(ca *storage.CertificateAuthority) (crypto.Signer, error) {
	keyPEM, err := r.keystore.DecryptPEM(ca.KeyEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt key for CA %q: %w", ca.Name, err)
	}
	return parseKeyPEM(keyPEM)
}

// generateDelegatedSigner creates a short-lived certificate explicitly for OCSP
func (r *OCSPResponder) generateDelegatedSigner(caCert *x509.Certificate, caKey crypto.Signer) (*x509.Certificate, crypto.Signer, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: caCert.Subject.CommonName + " OCSP Responder",
		},
		NotBefore: time.Now().Add(-5 * time.Minute),
		NotAfter:  time.Now().Add(7 * 24 * time.Hour),

		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5},
				Critical: false,
				Value:    []byte{0x05, 0x00},
			},
		},
	}

	// 3. Sign the throwaway cert with the master CA key
	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	delegatedCert, err := x509.ParseCertificate(derBytes)
	return delegatedCert, priv, err
}
