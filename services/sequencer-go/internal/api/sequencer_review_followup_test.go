package api

// Regression tests for the third-pass review of H-2:
//
//   1. `metrics.PreparedPending` must not underflow when `prepareRecord`
//      aborts internally (contract-validation or SignRoot failure). Before
//      the fix, the gauge was incremented in the caller AFTER `prepareRecord`
//      returned, so an internal abort decremented a counter that had never
//      been incremented.
//
//   2. `/v1/queue-leaf-hash` must pass the user-supplied 32-byte value hash
//      to Rust via the `pre_hashed_value_hash` field, NOT via
//      `canonical_content` — otherwise the Rust service hashes it a second
//      time and the leaf value committed to the SMT differs from what
//      external (Python / Halo2) verifiers expect.

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	pb "github.com/OlympusLedgerOrg/Olympus/services/sequencer/proto"
)

// ---------------------------------------------------------------------------
// Fix 1: gauge does not underflow on internal `prepareRecord` failures
// ---------------------------------------------------------------------------

// signFailingSMT extends fakeSMT with a SignRoot that always fails. SignRoot
// is invoked by `prepareRecord` AFTER PrepareUpdate has succeeded, so the
// failure path forces `prepareRecord` to call `bestEffortAbort` itself —
// the exact path that previously underflowed the gauge.
type signFailingSMT struct {
	*fakeSMT
}

func (s *signFailingSMT) SignRoot(_ context.Context, _ []byte, _ uint64, _ map[string]string) (*pb.SignRootResponse, error) {
	s.signCalls.Add(1)
	return nil, errors.New("sign deliberately fails")
}

// TestPreparedPendingGauge_NoUnderflow_OnSignFailure asserts that when
// SignRoot fails inside `prepareRecord`, the prepared-pending gauge ends
// up at exactly zero — not -1. The increment must happen inside
// `prepareRecord` immediately after PrepareUpdate succeeds so it is
// matched by the abort-side decrement.
func TestPreparedPendingGauge_NoUnderflow_OnSignFailure(t *testing.T) {
	smt := &signFailingSMT{fakeSMT: newFakeSMT()}
	seq, mreg := newTestSequencer(t, smt, &recordingStorage{})

	resp := doQueueLeaf(t, seq.Handler(), makeQueueLeafBody(t, "doc-sign-fail"))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 on SignRoot failure, got %d", resp.StatusCode)
	}

	// Prepare ran, abort ran, no commit.
	if got := smt.prepareCalls.Load(); got != 1 {
		t.Fatalf("PrepareUpdate calls: want 1, got %d", got)
	}
	if got := smt.abortCalls.Load(); got != 1 {
		t.Fatalf("AbortPreparedUpdate calls: want 1, got %d", got)
	}
	if got := smt.commitCalls.Load(); got != 0 {
		t.Fatalf("CommitPreparedUpdate calls: want 0, got %d", got)
	}

	// Critical: the gauge must be exactly zero, NOT -1.
	if got := mreg.PreparedPending.Value(); got != 0 {
		t.Fatalf("PreparedPending must be 0 after balanced inc/dec, got %d (gauge underflow!)", got)
	}
	// And the abort counter must record exactly the one rollback.
	if got := mreg.AbortsAfterDBFailure.Value(); got != 1 {
		t.Fatalf("AbortsAfterDBFailure: want 1, got %d", got)
	}
	if got := mreg.CommitsAfterDBSuccess.Value(); got != 0 {
		t.Fatalf("CommitsAfterDBSuccess: want 0, got %d", got)
	}
}

// contractViolatingSMT returns a PrepareUpdateResponse with a wrong-length
// NewRoot, forcing the contract check inside `prepareRecord` to call
// `bestEffortAbort`. This is the *other* internal-abort branch that was
// underflowing the gauge before the fix.
type contractViolatingSMT struct {
	*fakeSMT
}

func (c *contractViolatingSMT) PrepareUpdate(ctx context.Context, shardID string, recordKey *pb.RecordKey, canonicalContent []byte, preHashedValueHash []byte, parserID string, canonicalParserVersion string) (*pb.PrepareUpdateResponse, error) {
	resp, err := c.fakeSMT.PrepareUpdate(ctx, shardID, recordKey, canonicalContent, preHashedValueHash, parserID, canonicalParserVersion)
	if err != nil {
		return resp, err
	}
	resp.NewRoot = []byte{0x00} // wrong length on purpose
	return resp, nil
}

func TestPreparedPendingGauge_NoUnderflow_OnContractViolation(t *testing.T) {
	smt := &contractViolatingSMT{fakeSMT: newFakeSMT()}
	seq, mreg := newTestSequencer(t, smt, &recordingStorage{})

	resp := doQueueLeaf(t, seq.Handler(), makeQueueLeafBody(t, "doc-bad-contract"))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 on contract violation, got %d", resp.StatusCode)
	}
	if got := smt.abortCalls.Load(); got != 1 {
		t.Fatalf("AbortPreparedUpdate calls: want 1, got %d", got)
	}
	if got := mreg.PreparedPending.Value(); got != 0 {
		t.Fatalf("PreparedPending must be 0, got %d (gauge underflow!)", got)
	}
}

// TestPreparedPendingGauge_BalancedAcrossManyFailures stress-tests the
// invariant under many sequential SignRoot failures: the gauge must not
// drift in either direction, no matter how many times the failure path
// runs. Without the fix this would land at -100 after 100 failures.
func TestPreparedPendingGauge_BalancedAcrossManyFailures(t *testing.T) {
	smt := &signFailingSMT{fakeSMT: newFakeSMT()}
	seq, mreg := newTestSequencer(t, smt, &recordingStorage{})

	const N = 100
	for i := 0; i < N; i++ {
		_ = doQueueLeaf(t, seq.Handler(), makeQueueLeafBody(t, "doc-rep"))
	}
	if got := mreg.PreparedPending.Value(); got != 0 {
		t.Fatalf("after %d sign-failures gauge must be 0, got %d", N, got)
	}
	if got := mreg.AbortsAfterDBFailure.Value(); got != N {
		t.Fatalf("AbortsAfterDBFailure: want %d, got %d", N, got)
	}
}

// ---------------------------------------------------------------------------
// Fix 2: /v1/queue-leaf-hash sends value via pre_hashed_value_hash, not
// canonical_content (so Rust does not double-hash)
// ---------------------------------------------------------------------------

// hashRoutingFakeSMT is a fakeSMT that captures, on each PrepareUpdate, the
// arguments it was called with. Tests then assert on those captures.
type hashRoutingFakeSMT struct {
	*fakeSMT
	lastCanonicalContent   atomic.Pointer[[]byte]
	lastPreHashedValueHash atomic.Pointer[[]byte]
}

func (h *hashRoutingFakeSMT) PrepareUpdate(ctx context.Context, shardID string, recordKey *pb.RecordKey, canonicalContent []byte, preHashedValueHash []byte, parserID string, canonicalParserVersion string) (*pb.PrepareUpdateResponse, error) {
	cc := append([]byte(nil), canonicalContent...)
	pv := append([]byte(nil), preHashedValueHash...)
	h.lastCanonicalContent.Store(&cc)
	h.lastPreHashedValueHash.Store(&pv)
	return h.fakeSMT.PrepareUpdate(ctx, shardID, recordKey, canonicalContent, preHashedValueHash, parserID, canonicalParserVersion)
}

// TestQueueLeafHash_RoutesValueViaPreHashedField is the headline regression
// test for the double-hashing fix: the user-supplied 32-byte value hash
// MUST appear on the wire as `pre_hashed_value_hash`, with `canonical_content`
// empty. If the values were swapped (the pre-fix behaviour) Rust would
// BLAKE3 the hash a second time, producing a leaf value the caller cannot
// reproduce.
func TestQueueLeafHash_RoutesValueViaPreHashedField(t *testing.T) {
	smt := &hashRoutingFakeSMT{fakeSMT: newFakeSMT()}
	seq, _ := newTestSequencer(t, smt, &recordingStorage{})

	want := bytes.Repeat([]byte{0xAB}, 32)
	resp := doQueueLeafHash(t, seq.Handler(), makeQueueLeafHashBody(t, "doc-pre-hashed", want))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	gotPre := h32(smt.lastPreHashedValueHash.Load())
	gotCC := h32(smt.lastCanonicalContent.Load())

	if !bytes.Equal(gotPre, want) {
		t.Fatalf("pre_hashed_value_hash on the wire: want %x, got %x", want, gotPre)
	}
	if len(gotCC) != 0 {
		t.Fatalf("canonical_content must be empty for /v1/queue-leaf-hash to avoid double-hash, got %d bytes (%x)", len(gotCC), gotCC)
	}

	// Critically: Canonicalize must NOT have been called on the
	// pre-hashed path either (otherwise the user's bytes would have been
	// re-canonicalized as opaque content).
	if smt.canonCalls.Load() != 0 {
		t.Fatalf("Canonicalize must not be called on /v1/queue-leaf-hash, got %d", smt.canonCalls.Load())
	}
}

// TestQueueLeafHash_LeafValueHashEqualsRequestValueHash closes the loop
// end-to-end: the leaf value the fake stores is byte-equal to the value
// hash supplied in the request. With the pre-fix wiring (sending the value
// as canonical_content), the fake — which mirrors Rust's
// resolve_leaf_value_hash semantics — would have copied content into vh,
// but the real Rust service would have hashed it. This test pins the
// "no double-hash" contract on the Go side; the matching Rust regression
// lives in `resolve_leaf_value_hash_pre_hashed_is_returned_verbatim`.
func TestQueueLeafHash_LeafValueHashEqualsRequestValueHash(t *testing.T) {
	smt := newFakeSMT()
	seq, _ := newTestSequencer(t, smt, &recordingStorage{})

	want := bytes.Repeat([]byte{0xCD}, 32)
	resp := doQueueLeafHash(t, seq.Handler(), makeQueueLeafHashBody(t, "doc-equal", want))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// The fake stores vh = preHashedValueHash when supplied (mirrors the
	// Rust contract). So the response's leaf_value_hash must equal `want`.
	body := readBody(t, resp)
	wantHex := bytesToHex(want)
	if !strings.Contains(body, "\"leaf_value_hash\":\""+wantHex+"\"") {
		t.Fatalf("response leaf_value_hash must equal request value_hash %s, body=%q", wantHex, body)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func h32(p *[]byte) []byte {
	if p == nil {
		return nil
	}
	return *p
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return buf.String()
}

func bytesToHex(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[2*i] = hex[x>>4]
		out[2*i+1] = hex[x&0x0f]
	}
	return string(out)
}
