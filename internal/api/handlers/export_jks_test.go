package handlers

import (
	"bytes"
	"testing"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

func TestExportJKS_RoundTrip(t *testing.T) {
	leafPEM, keyPEM, _, _ := genSelfSignedForP12(t, "leaf.example.com")
	rootPEM, _, _, _ := genSelfSignedForP12(t, "Test Root")
	chainPEM := append(append([]byte{}, leafPEM...), rootPEM...)

	data, err := exportJKS(leafPEM, chainPEM, keyPEM, "testpass", "mint-ca")
	if err != nil {
		t.Fatalf("exportJKS: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("empty jks data")
	}

	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(data), []byte("testpass")); err != nil {
		t.Fatalf("load jks: %v", err)
	}
	if !ks.IsPrivateKeyEntry("mint-ca") {
		t.Fatal("expected a private key entry under alias mint-ca")
	}
	entry, err := ks.GetPrivateKeyEntry("mint-ca", []byte("testpass"))
	if err != nil {
		t.Fatalf("get private key entry: %v", err)
	}
	if len(entry.CertificateChain) != 2 {
		t.Fatalf("expected 2 certs in chain (leaf+root), got %d", len(entry.CertificateChain))
	}
}

func TestExportJKS_NoKey_Errors(t *testing.T) {
	leafPEM, _, _, _ := genSelfSignedForP12(t, "leaf.example.com")
	if _, err := exportJKS(leafPEM, leafPEM, nil, "testpass", "mint-ca"); err == nil {
		t.Fatal("expected error when key is missing")
	}
}

func TestExportJKS_WrongPassword_Fails(t *testing.T) {
	leafPEM, keyPEM, _, _ := genSelfSignedForP12(t, "leaf.example.com")
	data, err := exportJKS(leafPEM, leafPEM, keyPEM, "testpass", "mint-ca")
	if err != nil {
		t.Fatalf("exportJKS: %v", err)
	}
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(data), []byte("wrong")); err == nil {
		t.Fatal("expected load failure with wrong password")
	}
}
