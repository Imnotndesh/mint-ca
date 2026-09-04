package webauthn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"mint-ca/internal/attestation"

	"github.com/fxamacker/cbor/v2"
)

func buildAuthData(t *testing.T, credID []byte, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	rpIDHash := make([]byte, 32)
	flags := byte(0x41) // UP | AT
	signCount := make([]byte, 4)
	aaguid := make([]byte, 16)

	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(credID)))

	coseKey := map[int]interface{}{
		1:  2, // kty: EC2
		3:  -7,
		-1: 1, // crv: P-256
		-2: pub.X.Bytes(),
		-3: pub.Y.Bytes(),
	}
	coseKeyBytes, err := cbor.Marshal(coseKey)
	if err != nil {
		t.Fatalf("marshal cose key: %v", err)
	}

	var authData []byte
	authData = append(authData, rpIDHash...)
	authData = append(authData, flags)
	authData = append(authData, signCount...)
	authData = append(authData, aaguid...)
	authData = append(authData, credIDLen...)
	authData = append(authData, credID...)
	authData = append(authData, coseKeyBytes...)
	return authData
}

func buildStatement(t *testing.T, csrDER []byte, key *ecdsa.PrivateKey, tamperChallenge bool) attestation.Statement {
	t.Helper()
	challengeDigest := sha256.Sum256(csrDER)
	challenge := challengeDigest[:]
	if tamperChallenge {
		challenge = sha256.New().Sum([]byte("wrong"))
	}
	cd := clientData{
		Type:      "webauthn.create",
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Origin:    "https://example.com",
	}
	cdBytes, err := json.Marshal(cd)
	if err != nil {
		t.Fatalf("marshal clientData: %v", err)
	}
	clientDataHash := sha256.Sum256(cdBytes)

	credID := []byte("cred-1")
	authData := buildAuthData(t, credID, &key.PublicKey)

	signedData := append(append([]byte{}, authData...), clientDataHash[:]...)
	digest := sha256.Sum256(signedData)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	attStmt, err := cbor.Marshal(map[string]interface{}{
		"alg": -7,
		"sig": sig,
	})
	if err != nil {
		t.Fatalf("marshal attStmt: %v", err)
	}
	attObj, err := cbor.Marshal(map[string]interface{}{
		"fmt":      "packed",
		"attStmt":  cbor.RawMessage(attStmt),
		"authData": authData,
	})
	if err != nil {
		t.Fatalf("marshal attestationObject: %v", err)
	}

	data, _ := json.Marshal(statement{
		ClientDataJSONB64:    base64.RawURLEncoding.EncodeToString(cdBytes),
		AttestationObjectB64: base64.RawURLEncoding.EncodeToString(attObj),
	})
	return attestation.Statement{Format: Format, Data: data}
}

func TestVerify_SelfAttestedPacked_Succeeds(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER := []byte("pretend-csr-bytes")
	stmt := buildStatement(t, csrDER, key, false)

	v := New()
	res, err := v.Verify(context.Background(), csrDER, stmt)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Verified {
		t.Error("expected Verified=true")
	}
}

func TestVerify_ChallengeMismatch_Fails(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER := []byte("pretend-csr-bytes")
	stmt := buildStatement(t, csrDER, key, true)

	v := New()
	_, err = v.Verify(context.Background(), csrDER, stmt)
	if err == nil {
		t.Fatal("expected a challenge mismatch error")
	}
}

func TestVerify_WrongCSR_Fails(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	stmt := buildStatement(t, []byte("csr-a"), key, false)

	v := New()
	_, err = v.Verify(context.Background(), []byte("csr-b"), stmt)
	if err == nil {
		t.Fatal("expected verification to fail for a mismatched CSR")
	}
}

func TestVerify_UnsupportedFormat_Fails(t *testing.T) {
	cd := clientData{Type: "webauthn.create", Challenge: base64.RawURLEncoding.EncodeToString(sha256Sum([]byte("x")))}
	cdBytes, _ := json.Marshal(cd)
	attObj, _ := cbor.Marshal(map[string]interface{}{
		"fmt":      "android-key",
		"attStmt":  cbor.RawMessage{0xa0}, // empty map
		"authData": []byte{},
	})
	data, _ := json.Marshal(statement{
		ClientDataJSONB64:    base64.RawURLEncoding.EncodeToString(cdBytes),
		AttestationObjectB64: base64.RawURLEncoding.EncodeToString(attObj),
	})
	v := New()
	_, err := v.Verify(context.Background(), []byte("x"), attestation.Statement{Format: Format, Data: data})
	if err == nil {
		t.Fatal("expected an unsupported-format error")
	}
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
