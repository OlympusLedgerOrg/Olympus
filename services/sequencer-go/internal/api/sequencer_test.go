package api

import (
"bytes"
"context"
"encoding/json"
"errors"
"net/http"
"net/http/httptest"
"strings"
"testing"

"github.com/OlympusLedgerOrg/Olympus/services/sequencer/internal/storage"
)

// mockStorage is a test double for storageQuerier. It serves pre-loaded roots
// by tree size and returns a configurable error for any unknown size.
type mockStorage struct {
roots map[uint64]*storage.SignedRoot
err   error
}

func (m *mockStorage) StoreLeafAndDeltas(_ context.Context, _ []storage.SmtDelta, _ []byte, _ uint64, _ []byte, _ storage.LeafEntry) error {
return nil
}

func (m *mockStorage) StoreLeafAndDeltasBatch(_ context.Context, _ []storage.BatchLeaf) error {
return nil
}

func (m *mockStorage) GetLatestRoot(_ context.Context) ([]byte, uint64, error) {
return make([]byte, 32), 0, nil
}

func (m *mockStorage) GetRootByTreeSize(_ context.Context, treeSize uint64) (*storage.SignedRoot, error) {
if root, ok := m.roots[treeSize]; ok {
return root, nil
}
if m.err != nil {
return nil, m.err
}
return nil, errors.New("not found")
}

// TestHandleConsistencyProofGone verifies the deprecation contract for the
// renamed /v1/get-consistency-proof route. The contract is part of the
// "one release window" deprecation policy documented in CHANGELOG.md and
// services/sequencer-go/README.md, so it should be locked down with a
// regression test.
func TestHandleConsistencyProofGone(t *testing.T) {
const token = "test-token"
s := &Sequencer{token: token}
handler := requireToken(s.token, s.handleConsistencyProofGone)

// Pre-condition: the deprecation handler still runs behind requireToken
// (otherwise it would leak existence of the route to unauthenticated
// callers, which is inconsistent with the rest of the API surface).
t.Run("requires token", func(t *testing.T) {
req := httptest.NewRequest(http.MethodGet, "/v1/get-consistency-proof", nil)
w := httptest.NewRecorder()
handler(w, req)
if w.Code != http.StatusUnauthorized {
t.Fatalf("expected 401 without token, got %d", w.Code)
}
})

t.Run("returns 410 Gone with successor link", func(t *testing.T) {
req := httptest.NewRequest(http.MethodGet, "/v1/get-consistency-proof", nil)
req.Header.Set("X-Sequencer-Token", token)
w := httptest.NewRecorder()
handler(w, req)

if w.Code != http.StatusGone {
t.Fatalf("expected 410 Gone, got %d", w.Code)
}

if got := w.Header().Get("Deprecation"); got != "true" {
t.Errorf("expected Deprecation: true header, got %q", got)
}

linkHdr := w.Header().Get("Link")
if !strings.Contains(linkHdr, "/v1/get-signed-root-pair") {
t.Errorf("expected Link header to point to /v1/get-signed-root-pair, got %q", linkHdr)
}
if !strings.Contains(linkHdr, `rel="successor-version"`) {
t.Errorf("expected Link header to declare successor-version rel, got %q", linkHdr)
}

if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
t.Errorf("expected JSON Content-Type, got %q", ct)
}

var body map[string]string
if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
t.Fatalf("expected JSON body, decode failed: %v", err)
}

// The body must name the successor path so a confused external
// verifier can re-target without reading docs.
if body["successor"] != "/v1/get-signed-root-pair" {
t.Errorf("expected successor=/v1/get-signed-root-pair, got %q", body["successor"])
}
if body["error"] != "endpoint_renamed" {
t.Errorf("expected error=endpoint_renamed, got %q", body["error"])
}
if body["message"] == "" {
t.Error("expected non-empty message field")
}
})
}

// TestHandleGetSignedRootPairValidation locks in the input-validation
// contract for the new /v1/get-signed-root-pair endpoint. The success path
// (storage hit + signed-root marshaling) requires Postgres and the Rust
// CD-HS-ST service and is exercised by the existing integration tests; the
// validation paths short-circuit before any storage access and are
// therefore safely testable as pure unit tests against a Sequencer with a
// nil storage backend. This test will reliably fail if any of the
// pre-storage guards are removed or reordered.
func TestHandleGetSignedRootPairValidation(t *testing.T) {
const token = "test-token"
// storage left nil on purpose: every assertion below must short-circuit
// before s.storage is dereferenced. If a future change reorders the
// guards, this test will panic with a nil-deref instead of silently
// passing — which is the desired loud failure.
s := &Sequencer{token: token}
handler := requireToken(s.token, s.handleGetSignedRootPair)

t.Run("requires token", func(t *testing.T) {
req := httptest.NewRequest(http.MethodGet, "/v1/get-signed-root-pair?old_tree_size=1&new_tree_size=2", nil)
w := httptest.NewRecorder()
handler(w, req)
if w.Code != http.StatusUnauthorized {
t.Fatalf("expected 401 without token, got %d", w.Code)
}
})

t.Run("rejects non-GET methods", func(t *testing.T) {
req := httptest.NewRequest(http.MethodPost, "/v1/get-signed-root-pair?old_tree_size=1&new_tree_size=2", nil)
req.Header.Set("X-Sequencer-Token", token)
w := httptest.NewRecorder()
handler(w, req)
if w.Code != http.StatusMethodNotAllowed {
t.Fatalf("expected 405 for POST, got %d", w.Code)
}
})

t.Run("requires both tree-size parameters", func(t *testing.T) {
cases := []struct {
name, query string
}{
{"missing both", ""},
{"missing new", "old_tree_size=1"},
{"missing old", "new_tree_size=2"},
}
for _, tc := range cases {
t.Run(tc.name, func(t *testing.T) {
req := httptest.NewRequest(http.MethodGet, "/v1/get-signed-root-pair?"+tc.query, nil)
req.Header.Set("X-Sequencer-Token", token)
w := httptest.NewRecorder()
handler(w, req)
if w.Code != http.StatusBadRequest {
t.Fatalf("expected 400, got %d (body=%q)", w.Code, w.Body.String())
}
})
}
})

t.Run("rejects non-numeric tree sizes", func(t *testing.T) {
cases := []string{
"old_tree_size=abc&new_tree_size=2",
"old_tree_size=1&new_tree_size=xyz",
"old_tree_size=-1&new_tree_size=2",
}
for _, q := range cases {
req := httptest.NewRequest(http.MethodGet, "/v1/get-signed-root-pair?"+q, nil)
req.Header.Set("X-Sequencer-Token", token)
w := httptest.NewRecorder()
handler(w, req)
if w.Code != http.StatusBadRequest {
t.Fatalf("query %q: expected 400, got %d", q, w.Code)
}
}
})

t.Run("rejects old_tree_size > new_tree_size", func(t *testing.T) {
req := httptest.NewRequest(http.MethodGet, "/v1/get-signed-root-pair?old_tree_size=10&new_tree_size=5", nil)
req.Header.Set("X-Sequencer-Token", token)
w := httptest.NewRecorder()
handler(w, req)
if w.Code != http.StatusBadRequest {
t.Fatalf("expected 400 for inverted sizes, got %d", w.Code)
}
if !strings.Contains(w.Body.String(), "exceed") {
t.Errorf("expected ordering error in body, got %q", w.Body.String())
}
})
}

// TestHandleGetSignedRootPairStorage covers the storage-dependent paths of
// /v1/get-signed-root-pair: root-not-found (404) and a happy-path success
// (200) that verifies the response body shape. Input-validation paths are
// covered by TestHandleGetSignedRootPairValidation above.
func TestHandleGetSignedRootPairStorage(t *testing.T) {
const token = "test-token"

oldRoot := &storage.SignedRoot{
RootHash:  bytes.Repeat([]byte{0xaa}, 32),
TreeSize:  5,
Signature: bytes.Repeat([]byte{0xbb}, 64),
}
newRoot := &storage.SignedRoot{
RootHash:  bytes.Repeat([]byte{0xcc}, 32),
TreeSize:  10,
Signature: bytes.Repeat([]byte{0xdd}, 64),
}

// Full store: both tree sizes present.
fullStore := &mockStorage{
roots: map[uint64]*storage.SignedRoot{5: oldRoot, 10: newRoot},
err:   errors.New("not found"),
}
s := &Sequencer{token: token, storage: fullStore}
handler := requireToken(s.token, s.handleGetSignedRootPair)

t.Run("old root not found returns 404", func(t *testing.T) {
// Neither tree size 99 nor 100 is in the store.
req := httptest.NewRequest(http.MethodGet, "/v1/get-signed-root-pair?old_tree_size=99&new_tree_size=100", nil)
req.Header.Set("X-Sequencer-Token", token)
w := httptest.NewRecorder()
handler(w, req)
if w.Code != http.StatusNotFound {
t.Fatalf("expected 404, got %d", w.Code)
}
})

t.Run("new root not found returns 404", func(t *testing.T) {
// old_tree_size=5 exists; new_tree_size=99 does not.
partialStore := &mockStorage{
roots: map[uint64]*storage.SignedRoot{5: oldRoot},
err:   errors.New("not found"),
}
s2 := &Sequencer{token: token, storage: partialStore}
h2 := requireToken(s2.token, s2.handleGetSignedRootPair)
req := httptest.NewRequest(http.MethodGet, "/v1/get-signed-root-pair?old_tree_size=5&new_tree_size=99", nil)
req.Header.Set("X-Sequencer-Token", token)
w := httptest.NewRecorder()
h2(w, req)
if w.Code != http.StatusNotFound {
t.Fatalf("expected 404, got %d", w.Code)
}
})

t.Run("success returns signed root pair", func(t *testing.T) {
req := httptest.NewRequest(http.MethodGet, "/v1/get-signed-root-pair?old_tree_size=5&new_tree_size=10", nil)
req.Header.Set("X-Sequencer-Token", token)
w := httptest.NewRecorder()
handler(w, req)

if w.Code != http.StatusOK {
t.Fatalf("expected 200, got %d", w.Code)
}
if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
t.Errorf("expected JSON Content-Type, got %q", ct)
}

var body map[string]interface{}
if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
t.Fatalf("expected JSON body, decode failed: %v", err)
}

if got := body["old_tree_size"]; got != float64(5) {
t.Errorf("expected old_tree_size=5, got %v", got)
}
if got := body["new_tree_size"]; got != float64(10) {
t.Errorf("expected new_tree_size=10, got %v", got)
}
// old_root is 0xaa repeated 32 times — 64 hex characters.
wantOldRoot := strings.Repeat("aa", 32)
if got, _ := body["old_root"].(string); got != wantOldRoot {
t.Errorf("expected old_root=%q, got %q", wantOldRoot, got)
}
wantNewRoot := strings.Repeat("cc", 32)
if got, _ := body["new_root"].(string); got != wantNewRoot {
t.Errorf("expected new_root=%q, got %q", wantNewRoot, got)
}
if _, ok := body["old_signature"]; !ok {
t.Error("expected old_signature field in response body")
}
if _, ok := body["new_signature"]; !ok {
t.Error("expected new_signature field in response body")
}
})
}
