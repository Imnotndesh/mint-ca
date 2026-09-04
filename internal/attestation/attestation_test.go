package attestation

import (
	"context"
	"testing"
)

type fakeVerifier struct {
	format string
	result Result
	err    error
	called bool
}

func (f *fakeVerifier) Format() string { return f.format }
func (f *fakeVerifier) Verify(ctx context.Context, csrDER []byte, stmt Statement) (Result, error) {
	f.called = true
	return f.result, f.err
}

func TestRegistry_DispatchesByFormat(t *testing.T) {
	r := NewRegistry()
	tpm := &fakeVerifier{format: "tpm2", result: Result{Verified: true, KeyID: "ek-1"}}
	wa := &fakeVerifier{format: "webauthn", result: Result{Verified: true, KeyID: "cred-1"}}
	r.Register(tpm)
	r.Register(wa)

	res, err := r.Verify(context.Background(), []byte("csr"), Statement{Format: "tpm2"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !tpm.called || wa.called {
		t.Error("expected only the tpm2 verifier to be invoked")
	}
	if res.KeyID != "ek-1" {
		t.Errorf("KeyID = %q", res.KeyID)
	}
}

func TestRegistry_UnknownFormatErrors(t *testing.T) {
	r := NewRegistry()
	_, err := r.Verify(context.Background(), nil, Statement{Format: "unknown"})
	if err == nil {
		t.Fatal("expected an error for an unregistered format")
	}
}

func TestRegistry_LaterRegisterReplaces(t *testing.T) {
	r := NewRegistry()
	first := &fakeVerifier{format: "tpm2", result: Result{KeyID: "first"}}
	second := &fakeVerifier{format: "tpm2", result: Result{KeyID: "second"}}
	r.Register(first)
	r.Register(second)

	res, err := r.Verify(context.Background(), nil, Statement{Format: "tpm2"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.KeyID != "second" {
		t.Errorf("KeyID = %q, want second", res.KeyID)
	}
}

func TestRegistry_PropagatesVerifierError(t *testing.T) {
	r := NewRegistry()
	r.Register(&fakeVerifier{format: "tpm2", err: context.DeadlineExceeded})
	_, err := r.Verify(context.Background(), nil, Statement{Format: "tpm2"})
	if err == nil {
		t.Fatal("expected the verifier's error to propagate")
	}
}
