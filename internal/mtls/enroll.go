// Package mtls implements mutual-TLS device enrollment. A separate TLS listener
// requires devices to present a client certificate chained to a trusted issuer;
// the enrollment handler then issues a fresh leaf bound to the device's identity
// (its distinguished name and DNS identifiers) from the presented cert.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"

	"mint-ca/internal/ca"
	"mint-ca/internal/config"
	"mint-ca/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// EnrollHandler issues per-device leaves after mTLS authentication. The device
// authenticates with a client cert issued by the trusted enrollment CA.
type EnrollHandler struct {
	engine        *ca.Engine
	store         storage.Store
	issuerCAID    uuid.UUID
	provisionerID uuid.UUID
	// DefaultTTLSeconds is the issued leaf lifetime. 0 uses the engine default.
	DefaultTTLSeconds int64
	// StoreKey escrows the issued leaf key so the operator can re-provision.
	StoreKey bool
}

// NewEnrollHandler constructs an enrollment handler that signs device certs with
// issuerCAID under provisionerID.
func NewEnrollHandler(engine *ca.Engine, store storage.Store, issuerCAID, provisionerID uuid.UUID) *EnrollHandler {
	return &EnrollHandler{
		engine:        engine,
		store:         store,
		issuerCAID:    issuerCAID,
		provisionerID: provisionerID,
	}
}

// RegisterRoutes mounts the enrollment endpoints.
func (h *EnrollHandler) RegisterRoutes(r chi.Router) {
	r.Get("/healthz", h.health)
	r.Get("/enroll", h.enroll) // GET: simple, idempotent device bootstrap
}

func (h *EnrollHandler) health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("mint-ca mtls enroll: ok\n"))
}

// enroll issues a leaf for the authenticated device.
func (h *EnrollHandler) enroll(w http.ResponseWriter, r *http.Request) {
	peer := deviceCert(r)
	if peer == nil {
		http.Error(w, "no client certificate presented", http.StatusUnauthorized)
		return
	}
	cn := peer.Subject.CommonName
	if cn == "" {
		http.Error(w, "device certificate has no CommonName", http.StatusBadRequest)
		return
	}
	sansDNS := append([]string{cn}, peer.DNSNames...)

	issued, err := h.engine.IssueCert(r.Context(), ca.IssueCertRequest{
		CAID:          h.issuerCAID,
		ProvisionerID: h.provisionerID,
		Requester:     "mtls:" + cn,
		CommonName:    cn,
		SANsDNS:       sansDNS,
		KeyAlgo:       ca.KeyAlgoECDSAP256,
		TTLSeconds:    h.DefaultTTLSeconds,
		KeyUsage:      x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		StoreKey:      h.StoreKey,
		Metadata: storage.JSON{
			"device_id":  cn,
			"enrollment": "mtls",
		},
	})
	if err != nil {
		http.Error(w, "enrollment failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]interface{}{
		"certificate": issued.Record,
		"cert_pem":    string(issued.CertPEM),
		"key_pem":     string(issued.KeyPEM),
		"chain_pem":   string(issued.ChainPEM),
	})
}

// deviceCert returns the verified peer certificate, else nil.
func deviceCert(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	w.Write(append(b, '\n'))
}

// BuildServerTLSConfig produces the tls.Config for the enrollment listener: it
// requires and verifies a client certificate against the trusted client CA.
func BuildServerTLSConfig(cfg config.MTLSConfig, clientCAPEM []byte) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(clientCAPEM) {
		return nil, fmt.Errorf("mtls: no usable CA certs in client CA PEM")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
	}, nil
}
