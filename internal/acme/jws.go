package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// ------------------- raw JWS envelope -------------------

// RawJWS is the JSON structure sent in the body of every ACME POST request.
type RawJWS struct {
	Protected string `json:"protected"` // base64url-encoded protected header JSON
	Payload   string `json:"payload"`   // base64url-encoded payload JSON (may be "")
	Signature string `json:"signature"` // base64url-encoded signature bytes
}

// ProtectedHeader is the decoded JWS protected header.
type ProtectedHeader struct {
	Algorithm string          `json:"alg"`
	Nonce     string          `json:"nonce"`
	URL       string          `json:"url"`
	JWK       json.RawMessage `json:"jwk,omitempty"` // present on newAccount / revokeCert
	KID       string          `json:"kid,omitempty"` // present on all other requests
}

// ParseJWS decodes the base64url fields of a RawJWS without verifying the
// signature. Call VerifyJWS afterward to verify.
func (r *RawJWS) ParseProtected() (*ProtectedHeader, error) {
	protBytes, err := b64Decode(r.Protected)
	if err != nil {
		return nil, fmt.Errorf("jws: decode protected: %w", err)
	}
	var hdr ProtectedHeader
	if err := json.Unmarshal(protBytes, &hdr); err != nil {
		return nil, fmt.Errorf("jws: unmarshal protected: %w", err)
	}
	return &hdr, nil
}

// PayloadBytes decodes the payload field. Returns nil, nil for POST-as-GET
// (empty string payload).
func (r *RawJWS) PayloadBytes() ([]byte, error) {
	if r.Payload == "" {
		return nil, nil
	}
	b, err := b64Decode(r.Payload)
	if err != nil {
		return nil, fmt.Errorf("jws: decode payload: %w", err)
	}
	return b, nil
}

// Verify verifies the JWS signature over "protected.payload" using the
// supplied public key. It returns an error if the signature is invalid.
func (r *RawJWS) Verify(pub crypto.PublicKey, alg string) error {
	// The message is ASCII(BASE64URL(protected) || "." || BASE64URL(payload)).
	msg := []byte(r.Protected + "." + r.Payload)

	sigBytes, err := b64Decode(r.Signature)
	if err != nil {
		return fmt.Errorf("jws: decode signature: %w", err)
	}

	switch alg {
	case "ES256":
		return verifyECDSA(pub, crypto.SHA256, msg, sigBytes)
	case "ES384":
		return verifyECDSA(pub, crypto.SHA384, msg, sigBytes)
	case "RS256":
		return verifyRSAPKCS1v15(pub, crypto.SHA256, msg, sigBytes)
	case "RS384":
		return verifyRSAPKCS1v15(pub, crypto.SHA384, msg, sigBytes)
	case "RS512":
		return verifyRSAPKCS1v15(pub, crypto.SHA512, msg, sigBytes)
	case "PS256":
		return verifyRSAPSS(pub, crypto.SHA256, msg, sigBytes)
	case "PS384":
		return verifyRSAPSS(pub, crypto.SHA384, msg, sigBytes)
	case "PS512":
		return verifyRSAPSS(pub, crypto.SHA512, msg, sigBytes)
	default:
		return fmt.Errorf("jws: unsupported algorithm %q", alg)
	}
}

// ------------------- JWK decoding -------------------

// RawJWK is the JSON representation of a JSON Web Key.
type RawJWK struct {
	Kty string `json:"kty"`
	// ECDSA fields
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	// RSA fields
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
}

// ParseJWK decodes a JSON-encoded JWK into a Go public key.
func ParseJWK(raw json.RawMessage) (crypto.PublicKey, error) {
	var j RawJWK
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, fmt.Errorf("jwk: unmarshal: %w", err)
	}

	switch j.Kty {
	case "EC":
		return decodeECKey(j)
	case "RSA":
		return decodeRSAKey(j)
	default:
		return nil, fmt.Errorf("jwk: unsupported key type %q", j.Kty)
	}
}

func decodeECKey(j RawJWK) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch j.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("jwk: unsupported EC curve %q", j.Crv)
	}

	xBytes, err := b64Decode(j.X)
	if err != nil {
		return nil, fmt.Errorf("jwk: EC x: %w", err)
	}
	yBytes, err := b64Decode(j.Y)
	if err != nil {
		return nil, fmt.Errorf("jwk: EC y: %w", err)
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	if !curve.IsOnCurve(pub.X, pub.Y) {
		return nil, fmt.Errorf("jwk: EC point not on curve")
	}
	return pub, nil
}

func decodeRSAKey(j RawJWK) (*rsa.PublicKey, error) {
	nBytes, err := b64Decode(j.N)
	if err != nil {
		return nil, fmt.Errorf("jwk: RSA n: %w", err)
	}
	eBytes, err := b64Decode(j.E)
	if err != nil {
		return nil, fmt.Errorf("jwk: RSA e: %w", err)
	}

	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, fmt.Errorf("jwk: RSA exponent too large")
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(e.Int64()),
	}, nil
}

// ------------------- Thumbprint (RFC 7638) -------------------

// Thumbprint computes the JWK Thumbprint (SHA-256) of a public key as
// specified in RFC 7638. This is the canonical account key identifier used
// in ACME (stored as acme_accounts.key_id).
func Thumbprint(raw json.RawMessage) (string, error) {
	var j RawJWK
	if err := json.Unmarshal(raw, &j); err != nil {
		return "", fmt.Errorf("thumbprint: unmarshal jwk: %w", err)
	}

	// RFC 7638 §3.2: the thumbprint input is the JSON serialisation of the
	// required members only, in lexicographic order, no whitespace.
	var canonical []byte
	var err error

	switch j.Kty {
	case "EC":
		canonical, err = json.Marshal(map[string]string{
			"crv": j.Crv,
			"kty": j.Kty,
			"x":   j.X,
			"y":   j.Y,
		})
	case "RSA":
		canonical, err = json.Marshal(map[string]string{
			"e":   j.E,
			"kty": j.Kty,
			"n":   j.N,
		})
	default:
		return "", fmt.Errorf("thumbprint: unsupported key type %q", j.Kty)
	}
	if err != nil {
		return "", fmt.Errorf("thumbprint: marshal canonical: %w", err)
	}

	h := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
}

// KeyAuthorization computes the ACME key authorization string:
//
//	token + "." + base64url(SHA-256(JWK-Thumbprint-of-account-key))
//
// For http-01 the server must return exactly this string from the challenge URL.
// For dns-01 the server must publish base64url(SHA-256(keyAuth)) as a TXT record.
func KeyAuthorization(token string, accountKeyJWK json.RawMessage) (string, error) {
	thumb, err := Thumbprint(accountKeyJWK)
	if err != nil {
		return "", err
	}
	return token + "." + thumb, nil
}

// DNS01DigestAuthorization returns the base64url(SHA-256(keyAuthorization))
// value that must appear in the _acme-challenge DNS TXT record.
func DNS01DigestAuthorization(keyAuth string) string {
	h := sha256.Sum256([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func verifyECDSA(pub crypto.PublicKey, hash crypto.Hash, msg, sig []byte) error {
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("jws: key type mismatch: expected *ecdsa.PublicKey")
	}

	h := hash.New()
	h.Write(msg)
	digest := h.Sum(nil)

	// ACME ECDSA signatures are raw r||s (each coordinate padded to key size),
	// not DER-encoded. Detect format: if first byte is 0x30 it's DER.
	var r, s big.Int
	if len(sig) > 0 && sig[0] == 0x30 {
		// DER-encoded — some clients send this.
		if !ecdsa.VerifyASN1(ecKey, digest, sig) {
			return fmt.Errorf("jws: ECDSA signature invalid")
		}
		return nil
	}

	// Raw r||s format (RFC 7518 §3.4).
	half := len(sig) / 2
	r.SetBytes(sig[:half])
	s.SetBytes(sig[half:])

	if !ecdsa.Verify(ecKey, digest, &r, &s) {
		return fmt.Errorf("jws: ECDSA signature invalid")
	}
	return nil
}

func verifyRSAPKCS1v15(pub crypto.PublicKey, hash crypto.Hash, msg, sig []byte) error {
	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("jws: key type mismatch: expected *rsa.PublicKey")
	}
	h := hash.New()
	h.Write(msg)
	digest := h.Sum(nil)
	if err := rsa.VerifyPKCS1v15(rsaKey, hash, digest, sig); err != nil {
		return fmt.Errorf("jws: RSA PKCS1v15 signature invalid: %w", err)
	}
	return nil
}

func verifyRSAPSS(pub crypto.PublicKey, hash crypto.Hash, msg, sig []byte) error {
	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("jws: key type mismatch: expected *rsa.PublicKey")
	}
	h := hash.New()
	h.Write(msg)
	digest := h.Sum(nil)
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}
	if err := rsa.VerifyPSS(rsaKey, hash, digest, sig, opts); err != nil {
		return fmt.Errorf("jws: RSA PSS signature invalid: %w", err)
	}
	return nil
}

// ------------------- helpers -------------------

// b64Decode decodes base64url without padding (as used throughout ACME/JWS).
func b64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// B64Encode encodes bytes to base64url without padding.
func B64Encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// ConstantTimeEqual compares two strings in constant time.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
