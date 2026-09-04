// Package webauthn implements a WebAuthn/FIDO2 attestation.Verifier: it
// checks a browser/authenticator-produced attestation (as from
// navigator.credentials.create()) and binds it to a specific CSR by requiring
// the client-data challenge to equal sha256(csrDER).
//
// Supported attestation statement formats: "packed" (with an x5c attestation
// certificate, or self-attestation using the credential's own key) and
// "none" (structural/binding check only — no cryptographic proof the key
// lives in an authenticator). Other formats ("android-key", "android-safetynet",
// "fido-u2f", "tpm") are not implemented and return an error, so callers get a
// clear "unsupported" signal rather than a false pass.
package webauthn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"

	"mint-ca/internal/attestation"

	"github.com/fxamacker/cbor/v2"
)

// Format is the attestation.Statement.Format this verifier handles.
const Format = "webauthn"

// statement is the JSON shape expected in attestation.Statement.Data.
type statement struct {
	// ClientDataJSONB64 is the base64 (standard or raw-URL) encoding of the
	// authenticator's clientDataJSON.
	ClientDataJSONB64 string `json:"client_data_json_b64"`
	// AttestationObjectB64 is the base64 (standard or raw-URL) encoding of
	// the CBOR attestationObject.
	AttestationObjectB64 string `json:"attestation_object_b64"`
}

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

type attestationObject struct {
	Fmt      string          `cbor:"fmt"`
	AttStmt  cbor.RawMessage `cbor:"attStmt"`
	AuthData []byte          `cbor:"authData"`
}

type packedAttStmt struct {
	Alg int64    `cbor:"alg"`
	Sig []byte   `cbor:"sig"`
	X5C [][]byte `cbor:"x5c"`
}

// Verifier checks WebAuthn attestation statements.
type Verifier struct{}

// New builds a Verifier.
func New() *Verifier { return &Verifier{} }

// Format implements attestation.Verifier.
func (v *Verifier) Format() string { return Format }

// Verify implements attestation.Verifier.
func (v *Verifier) Verify(ctx context.Context, csrDER []byte, stmt attestation.Statement) (attestation.Result, error) {
	var s statement
	if err := json.Unmarshal(stmt.Data, &s); err != nil {
		return attestation.Result{}, fmt.Errorf("webauthn: parse statement: %w", err)
	}

	clientDataRaw, err := decodeB64(s.ClientDataJSONB64)
	if err != nil {
		return attestation.Result{}, fmt.Errorf("webauthn: decode client_data_json_b64: %w", err)
	}
	var cd clientData
	if err := json.Unmarshal(clientDataRaw, &cd); err != nil {
		return attestation.Result{}, fmt.Errorf("webauthn: parse clientDataJSON: %w", err)
	}
	if cd.Type != "webauthn.create" {
		return attestation.Result{}, fmt.Errorf("webauthn: unexpected clientData.type %q", cd.Type)
	}
	challenge, err := decodeB64(cd.Challenge)
	if err != nil {
		return attestation.Result{}, fmt.Errorf("webauthn: decode challenge: %w", err)
	}
	wantChallenge := sha256.Sum256(csrDER)
	if !bytesEqual(challenge, wantChallenge[:]) {
		return attestation.Result{}, fmt.Errorf("webauthn: challenge does not match this CSR")
	}

	attObjRaw, err := decodeB64(s.AttestationObjectB64)
	if err != nil {
		return attestation.Result{}, fmt.Errorf("webauthn: decode attestation_object_b64: %w", err)
	}
	var ao attestationObject
	if err := cbor.Unmarshal(attObjRaw, &ao); err != nil {
		return attestation.Result{}, fmt.Errorf("webauthn: decode attestationObject CBOR: %w", err)
	}

	authData, err := parseAuthData(ao.AuthData)
	if err != nil {
		return attestation.Result{}, fmt.Errorf("webauthn: parse authData: %w", err)
	}

	clientDataHash := sha256.Sum256(clientDataRaw)
	signedData := append(append([]byte{}, ao.AuthData...), clientDataHash[:]...)

	switch ao.Fmt {
	case "none":
		return attestation.Result{
			Verified: true,
			KeyID:    authData.credentialIDHex(),
			Metadata: map[string]string{"format": Format, "att_fmt": "none", "assurance": "binding-only, no attestation signature"},
		}, nil

	case "packed":
		var attStmt packedAttStmt
		if err := cbor.Unmarshal(ao.AttStmt, &attStmt); err != nil {
			return attestation.Result{}, fmt.Errorf("webauthn: decode packed attStmt: %w", err)
		}
		var pub crypto.PublicKey
		if len(attStmt.X5C) > 0 {
			cert, err := x509.ParseCertificate(attStmt.X5C[0])
			if err != nil {
				return attestation.Result{}, fmt.Errorf("webauthn: parse attestation certificate: %w", err)
			}
			pub = cert.PublicKey
		} else {
			pub, err = authData.publicKey()
			if err != nil {
				return attestation.Result{}, fmt.Errorf("webauthn: extract credential public key: %w", err)
			}
		}
		if err := verifyCOSESignature(pub, attStmt.Alg, signedData, attStmt.Sig); err != nil {
			return attestation.Result{}, fmt.Errorf("webauthn: attestation signature verification failed: %w", err)
		}
		return attestation.Result{
			Verified: true,
			KeyID:    authData.credentialIDHex(),
			Metadata: map[string]string{"format": Format, "att_fmt": "packed", "self_attested": fmt.Sprintf("%t", len(attStmt.X5C) == 0)},
		}, nil

	default:
		return attestation.Result{}, fmt.Errorf("webauthn: unsupported attestation format %q", ao.Fmt)
	}
}

func decodeB64(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// toInt64 normalizes the int64/uint64/int that CBOR decoding into
// interface{} may produce for a given map value.
func toInt64(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case uint64:
		return int64(n), true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// parsedAuthData is the subset of the WebAuthn authenticatorData structure
// this package needs.
type parsedAuthData struct {
	credentialID []byte
	coseKey      map[int]interface{}
}

func (a parsedAuthData) credentialIDHex() string {
	return fmt.Sprintf("%x", a.credentialID)
}

// publicKey decodes the COSE_Key map into a crypto.PublicKey. Supports COSE
// kty EC2 (2) and RSA (3), the two WebAuthn commonly issues.
func (a parsedAuthData) publicKey() (crypto.PublicKey, error) {
	kty, _ := toInt64(a.coseKey[1])
	switch kty {
	case 2: // EC2
		crv, _ := toInt64(a.coseKey[-1])
		x, _ := a.coseKey[-2].([]byte)
		y, _ := a.coseKey[-3].([]byte)
		var curve elliptic.Curve
		switch crv {
		case 1:
			curve = elliptic.P256()
		case 2:
			curve = elliptic.P384()
		case 3:
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC2 curve %d", crv)
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
	case 3: // RSA
		n, _ := a.coseKey[-1].([]byte)
		e, _ := a.coseKey[-2].([]byte)
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	default:
		return nil, fmt.Errorf("unsupported COSE key type %d", kty)
	}
}

// parseAuthData parses the fixed-layout prefix of authenticatorData plus its
// attestedCredentialData (required for an attestation response).
func parseAuthData(data []byte) (parsedAuthData, error) {
	const flagsOffset = 32
	const attestedCredentialDataFlag = 0x40
	if len(data) < 37 {
		return parsedAuthData{}, fmt.Errorf("authData too short (%d bytes)", len(data))
	}
	flags := data[flagsOffset]
	if flags&attestedCredentialDataFlag == 0 {
		return parsedAuthData{}, fmt.Errorf("authData has no attestedCredentialData (attestation response expected)")
	}
	rest := data[37:]
	if len(rest) < 18 {
		return parsedAuthData{}, fmt.Errorf("attestedCredentialData too short")
	}
	credIDLen := binary.BigEndian.Uint16(rest[16:18])
	rest = rest[18:]
	if len(rest) < int(credIDLen) {
		return parsedAuthData{}, fmt.Errorf("credentialId truncated")
	}
	credID := rest[:credIDLen]
	coseKeyRaw := rest[credIDLen:]

	var coseKey map[int]interface{}
	if err := cbor.Unmarshal(coseKeyRaw, &coseKey); err != nil {
		return parsedAuthData{}, fmt.Errorf("decode credentialPublicKey CBOR: %w", err)
	}
	return parsedAuthData{credentialID: credID, coseKey: coseKey}, nil
}

// verifyCOSESignature verifies sig over data under pub, per the COSE
// algorithm identifier alg (the small set WebAuthn commonly uses).
func verifyCOSESignature(pub crypto.PublicKey, alg int64, data, sig []byte) error {
	switch alg {
	case -7: // ES256
		digest := sha256.Sum256(data)
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("alg ES256 requires an EC public key, got %T", pub)
		}
		if !ecdsa.VerifyASN1(k, digest[:], sig) {
			return fmt.Errorf("ES256 signature does not verify")
		}
		return nil
	case -257: // RS256
		digest := sha256.Sum256(data)
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("alg RS256 requires an RSA public key, got %T", pub)
		}
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig)
	default:
		return fmt.Errorf("unsupported COSE algorithm %d", alg)
	}
}
