package acme

import (
	"context"
	"testing"

	"mint-ca/internal/ca"
	"mint-ca/internal/ca/revocation"
	mintcrypto "mint-ca/internal/crypto"
	"mint-ca/internal/storage"

	"github.com/google/uuid"
)

func setupRevokeTestEnv(t *testing.T) (*fakeStore, *ca.Engine, *revocation.CRLManager, *storage.CertificateAuthority) {
	t.Helper()
	store := newFakeStore()

	masterKey := make([]byte, 32)
	ks, err := mintcrypto.NewKeystore(masterKey)
	if err != nil {
		t.Fatalf("keystore: %v", err)
	}

	engine := ca.NewEngine(store, ks, "https://ca.test")
	crlMgr := revocation.NewCRLManager(store, ks)

	rootCA, err := engine.CreateRootCA(context.Background(), ca.CreateRootCARequest{
		Name: "root", CommonName: "Test Root", KeyAlgo: ca.KeyAlgoECDSAP256, TTLDays: 3650,
	})
	if err != nil {
		t.Fatalf("create root CA: %v", err)
	}
	return store, engine, crlMgr, rootCA
}

func TestRevokeCert_ByAccountKID(t *testing.T) {
	ctx := context.Background()
	store, engine, crlMgr, rootCA := setupRevokeTestEnv(t)

	account := &storage.ACMEAccount{ID: uuid.New(), Status: storage.ACMEAccountStatusValid}
	_ = store.CreateACMEAccount(ctx, account)

	issued, err := engine.IssueCert(ctx, ca.IssueCertRequest{
		CAID: rootCA.ID, ProvisionerID: uuid.New(),
		Requester:  "acme-account:" + account.ID.String(),
		CommonName: "leaf.example.com",
		KeyAlgo:    ca.KeyAlgoECDSAP256,
		TTLSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}

	svc := NewService(store, engine, NewNonceManager(store, 0), crlMgr, "https://ca.test")

	certDER := pemToDER(t, issued.CertPEM)
	if prob := svc.RevokeCert(ctx, certDER, account, nil, nil); prob != nil {
		t.Fatalf("RevokeCert failed: %v", prob)
	}

	got, _ := store.GetCertificateBySerial(ctx, issued.Record.Serial)
	if got.Status != storage.CertStatusRevoked {
		t.Errorf("expected cert revoked, got status %s", got.Status)
	}
}

func TestRevokeCert_WrongAccount_Fails(t *testing.T) {
	ctx := context.Background()
	store, engine, crlMgr, rootCA := setupRevokeTestEnv(t)

	owner := &storage.ACMEAccount{ID: uuid.New(), Status: storage.ACMEAccountStatusValid}
	attacker := &storage.ACMEAccount{ID: uuid.New(), Status: storage.ACMEAccountStatusValid}
	_ = store.CreateACMEAccount(ctx, owner)
	_ = store.CreateACMEAccount(ctx, attacker)

	issued, err := engine.IssueCert(ctx, ca.IssueCertRequest{
		CAID: rootCA.ID, ProvisionerID: uuid.New(),
		Requester:  "acme-account:" + owner.ID.String(),
		CommonName: "leaf2.example.com",
		KeyAlgo:    ca.KeyAlgoECDSAP256,
		TTLSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}

	svc := NewService(store, engine, NewNonceManager(store, 0), crlMgr, "https://ca.test")
	certDER := pemToDER(t, issued.CertPEM)

	prob := svc.RevokeCert(ctx, certDER, attacker, nil, nil)
	if prob == nil {
		t.Fatal("expected revocation by wrong account to fail")
	}
	if prob.Type != ErrUnauthorized {
		t.Errorf("expected unauthorized problem, got %s", prob.Type)
	}
}

func TestRevokeCert_AlreadyRevoked(t *testing.T) {
	ctx := context.Background()
	store, engine, crlMgr, rootCA := setupRevokeTestEnv(t)

	account := &storage.ACMEAccount{ID: uuid.New(), Status: storage.ACMEAccountStatusValid}
	_ = store.CreateACMEAccount(ctx, account)

	issued, err := engine.IssueCert(ctx, ca.IssueCertRequest{
		CAID: rootCA.ID, ProvisionerID: uuid.New(),
		Requester:  "acme-account:" + account.ID.String(),
		CommonName: "leaf3.example.com",
		KeyAlgo:    ca.KeyAlgoECDSAP256,
		TTLSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}

	svc := NewService(store, engine, NewNonceManager(store, 0), crlMgr, "https://ca.test")
	certDER := pemToDER(t, issued.CertPEM)

	if prob := svc.RevokeCert(ctx, certDER, account, nil, nil); prob != nil {
		t.Fatalf("first revoke failed: %v", prob)
	}
	prob := svc.RevokeCert(ctx, certDER, account, nil, nil)
	if prob == nil {
		t.Fatal("expected second revoke to fail")
	}
	if prob.Type != ErrAlreadyRevoked {
		t.Errorf("expected alreadyRevoked, got %s", prob.Type)
	}
}

func TestRevokeCert_BadReasonCode(t *testing.T) {
	ctx := context.Background()
	store, engine, crlMgr, rootCA := setupRevokeTestEnv(t)

	account := &storage.ACMEAccount{ID: uuid.New(), Status: storage.ACMEAccountStatusValid}
	_ = store.CreateACMEAccount(ctx, account)

	issued, err := engine.IssueCert(ctx, ca.IssueCertRequest{
		CAID: rootCA.ID, ProvisionerID: uuid.New(),
		Requester:  "acme-account:" + account.ID.String(),
		CommonName: "leaf4.example.com",
		KeyAlgo:    ca.KeyAlgoECDSAP256,
		TTLSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}

	svc := NewService(store, engine, NewNonceManager(store, 0), crlMgr, "https://ca.test")
	certDER := pemToDER(t, issued.CertPEM)

	badReason := 2 // cACompromise — disallowed for ACME clients
	prob := svc.RevokeCert(ctx, certDER, account, nil, &badReason)
	if prob == nil {
		t.Fatal("expected bad reason code to be rejected")
	}
	if prob.Type != ErrBadRevocationReason {
		t.Errorf("expected badRevocationReason, got %s", prob.Type)
	}
}

func pemToDER(t *testing.T, certPEM []byte) []byte {
	t.Helper()
	cert, err := parseCertPEMBytes(certPEM)
	if err != nil {
		t.Fatalf("parse cert PEM: %v", err)
	}
	return cert.Raw
}
