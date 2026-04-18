package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
