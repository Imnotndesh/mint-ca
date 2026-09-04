package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"mint-ca/internal/audit"

	"github.com/go-chi/chi/v5"
)

func TestAuditHandler_MerkleRoot(t *testing.T) {
	store := &auditChainFakeStore{logs: buildChain(5)}
	h := NewAuditHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/merkle/root", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if int(resp["size"].(float64)) != 5 {
		t.Errorf("expected size=5, got %+v", resp["size"])
	}
	if resp["root_hash"] == "" {
		t.Error("expected a non-empty root_hash")
	}
}

func TestAuditHandler_MerkleProof_VerifiesAgainstRoot(t *testing.T) {
	store := &auditChainFakeStore{logs: buildChain(9)}
	h := NewAuditHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	rootReq := httptest.NewRequest(http.MethodGet, "/api/v1/audit/merkle/root", nil)
	rootRec := httptest.NewRecorder()
	r.ServeHTTP(rootRec, rootReq)
	var rootResp map[string]interface{}
	_ = json.Unmarshal(rootRec.Body.Bytes(), &rootResp)
	rootHash := rootResp["root_hash"].(string)

	proofReq := httptest.NewRequest(http.MethodGet, "/api/v1/audit/merkle/proof/4", nil)
	proofRec := httptest.NewRecorder()
	r.ServeHTTP(proofRec, proofReq)
	if proofRec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", proofRec.Code, proofRec.Body.String())
	}
	var proofResp struct {
		Index     int      `json:"index"`
		Size      int      `json:"size"`
		EntryHash string   `json:"entry_hash"`
		Proof     []string `json:"proof"`
		RootHash  string   `json:"root_hash"`
	}
	if err := json.Unmarshal(proofRec.Body.Bytes(), &proofResp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if proofResp.RootHash != rootHash {
		t.Fatalf("proof root_hash %q != /merkle/root root_hash %q", proofResp.RootHash, rootHash)
	}

	ok, err := audit.VerifyInclusion(proofResp.EntryHash, proofResp.Index, proofResp.Size, proofResp.Proof, proofResp.RootHash)
	if err != nil {
		t.Fatalf("VerifyInclusion: %v", err)
	}
	if !ok {
		t.Error("expected the inclusion proof to verify")
	}
}

func TestAuditHandler_MerkleProof_IndexOutOfRange(t *testing.T) {
	store := &auditChainFakeStore{logs: buildChain(3)}
	h := NewAuditHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/merkle/proof/99", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestAuditHandler_MerkleProof_InvalidIndex(t *testing.T) {
	store := &auditChainFakeStore{logs: buildChain(3)}
	h := NewAuditHandler(store)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/merkle/proof/not-a-number", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
