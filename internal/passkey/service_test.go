package passkey

import (
	"context"
	"testing"

	"mint-ca/internal/storage"
)

type fakeStore struct {
	creds []*storage.PasskeyCredential
}

func (f *fakeStore) CreatePasskeyCredential(ctx context.Context, c *storage.PasskeyCredential) error {
	f.creds = append(f.creds, c)
	return nil
}
func (f *fakeStore) GetPasskeyCredential(ctx context.Context, id []byte) (*storage.PasskeyCredential, error) {
	for _, c := range f.creds {
		if string(c.ID) == string(id) {
			return c, nil
		}
	}
	return nil, nil
}
func (f *fakeStore) ListPasskeyCredentials(ctx context.Context) ([]*storage.PasskeyCredential, error) {
	return f.creds, nil
}
func (f *fakeStore) UpdatePasskeyCredential(ctx context.Context, c *storage.PasskeyCredential) error {
	return nil
}
func (f *fakeStore) DeletePasskeyCredential(ctx context.Context, id []byte) error { return nil }

func TestService_NewAndValidateStepUp(t *testing.T) {
	st := &fakeStore{}
	svc, err := New(st, Config{RPDisplayName: "mint-ca", RPID: "example.com", RPOrigins: []string{"https://example.com"}})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if svc.ValidateStepUp("") || svc.ValidateStepUp("nope") {
		t.Fatal("unknown step-up token must be invalid")
	}
	if svc.HasCredentials(context.Background()) {
		t.Fatal("no credentials expected initially")
	}
	st.creds = append(st.creds, &storage.PasskeyCredential{ID: []byte{1}})
	if !svc.HasCredentials(context.Background()) {
		t.Fatal("expected credential detected")
	}
}
