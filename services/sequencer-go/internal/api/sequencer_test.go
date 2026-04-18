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
