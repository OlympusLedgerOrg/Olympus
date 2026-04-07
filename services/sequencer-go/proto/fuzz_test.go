// Package proto_test contains fuzz tests for the protobuf unmarshaller at the
// Go/Rust CD-HS-ST service boundary.
//
// # Purpose
//
// These fuzz targets exercise the protobuf wire-format parser for every
// response message type that the Go sequencer receives from the Rust service.
// Because the Rust service may be upgraded independently, feeding arbitrary
// bytes into the unmarshal path acts as a quick CI gate against parser panics
// and memory-safety regressions introduced by schema drift.
//
// # Running
//
//	# CI gate — fixed corpus only (no mutation):
//	go test ./proto/ -run=Fuzz
//
//	# Short fuzzing run (10 s per target):
//	go test ./proto/ -run='^$' -fuzz=FuzzUnmarshalUpdateResponse   -fuzztime=10s
//	go test ./proto/ -run='^$' -fuzz=FuzzUnmarshalProveInclusion   -fuzztime=10s
//	go test ./proto/ -run='^$' -fuzz=FuzzUnmarshalCanonicalize     -fuzztime=10s
//	go test ./proto/ -run='^$' -fuzz=FuzzUnmarshalGetRoot          -fuzztime=10s
//	go test ./proto/ -run='^$' -fuzz=FuzzUnmarshalSignRoot         -fuzztime=10s
//
// # What constitutes a failure
//
// Any panic in proto.Unmarshal or proto.Marshal is a failure.
// Returning a non-nil error from proto.Unmarshal is acceptable — it means the
// fuzzer generated invalid wire data, which the real parser rejects cleanly.
package proto_test

import (
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/wombatvagina69-crypto/olympus/services/sequencer/proto"
)

// seedBytes encodes msg and panics if marshalling fails — used only for
// constructing in-process seed corpus entries.
func seedBytes(t testing.TB, msg proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("seed marshal: %v", err)
	}
	return b
}

// FuzzUnmarshalUpdateResponse fuzzes the UpdateResponse message — the most
// security-critical response from the Rust service, carrying the new SMT root,
// global key, leaf-value hash, and all node deltas to be persisted.
func FuzzUnmarshalUpdateResponse(f *testing.F) {
	// Seed: valid 32-byte root, key, and hash with a single node delta.
	zeros32 := make([]byte, 32)
	f.Add(seedBytes(f, &pb.UpdateResponse{
		NewRoot:       zeros32,
		GlobalKey:     zeros32,
		LeafValueHash: zeros32,
		Deltas: []*pb.SmtNodeDelta{
			{Path: []byte{0x80}, Level: 255, Hash: zeros32},
		},
	}))
	// Seed: empty response (zero-value message).
	f.Add(seedBytes(f, &pb.UpdateResponse{}))
	// Seed: maximum-depth delta list (256 siblings for a 256-level tree).
	deltas := make([]*pb.SmtNodeDelta, 256)
	for i := range deltas {
		deltas[i] = &pb.SmtNodeDelta{Level: uint32(i), Hash: zeros32}
	}
	f.Add(seedBytes(f, &pb.UpdateResponse{
		NewRoot: zeros32,
		Deltas:  deltas,
	}))
	// Seed: raw empty/garbage byte strings the fuzzer commonly explores.
	f.Add([]byte{})
	f.Add([]byte("\x00"))
	f.Add([]byte("\xff\xff\xff\xff\xff"))

	f.Fuzz(func(t *testing.T, data []byte) {
		msg := &pb.UpdateResponse{}
		if err := proto.Unmarshal(data, msg); err != nil {
			// Parse errors are expected for malformed input; not a failure.
			return
		}
		// If unmarshal succeeds, verify round-trip marshal stability.
		if _, err := proto.Marshal(msg); err != nil {
			t.Errorf("round-trip marshal after successful unmarshal: %v", err)
		}
	})
}

// FuzzUnmarshalProveInclusion fuzzes the ProveInclusionResponse message, which
// carries 256 sibling hashes used to reconstruct a Merkle path.
func FuzzUnmarshalProveInclusion(f *testing.F) {
	zeros32 := make([]byte, 32)
	siblings := make([][]byte, 256)
	for i := range siblings {
		siblings[i] = zeros32
	}
	f.Add(seedBytes(f, &pb.ProveInclusionResponse{
		GlobalKey: zeros32,
		ValueHash: zeros32,
		Siblings:  siblings,
		Root:      zeros32,
	}))
	f.Add(seedBytes(f, &pb.ProveInclusionResponse{}))
	f.Add([]byte{})
	f.Add([]byte("\x00"))

	f.Fuzz(func(t *testing.T, data []byte) {
		msg := &pb.ProveInclusionResponse{}
		if err := proto.Unmarshal(data, msg); err != nil {
			return
		}
		if _, err := proto.Marshal(msg); err != nil {
			t.Errorf("round-trip marshal after successful unmarshal: %v", err)
		}
	})
}

// FuzzUnmarshalProveNonInclusion fuzzes the ProveNonInclusionResponse message.
func FuzzUnmarshalProveNonInclusion(f *testing.F) {
	zeros32 := make([]byte, 32)
	siblings := make([][]byte, 256)
	for i := range siblings {
		siblings[i] = zeros32
	}
	f.Add(seedBytes(f, &pb.ProveNonInclusionResponse{
		GlobalKey: zeros32,
		Siblings:  siblings,
		Root:      zeros32,
	}))
	f.Add(seedBytes(f, &pb.ProveNonInclusionResponse{}))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg := &pb.ProveNonInclusionResponse{}
		if err := proto.Unmarshal(data, msg); err != nil {
			return
		}
		if _, err := proto.Marshal(msg); err != nil {
			t.Errorf("round-trip marshal after successful unmarshal: %v", err)
		}
	})
}

// FuzzUnmarshalCanonicalize fuzzes the CanonicalizeResponse message, which
// carries the canonical bytes and their BLAKE3 hash from the Rust service.
func FuzzUnmarshalCanonicalize(f *testing.F) {
	zeros32 := make([]byte, 32)
	f.Add(seedBytes(f, &pb.CanonicalizeResponse{
		CanonicalContent: []byte(`{"key":"value"}`),
		ContentHash:      zeros32,
	}))
	f.Add(seedBytes(f, &pb.CanonicalizeResponse{}))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg := &pb.CanonicalizeResponse{}
		if err := proto.Unmarshal(data, msg); err != nil {
			return
		}
		if _, err := proto.Marshal(msg); err != nil {
			t.Errorf("round-trip marshal after successful unmarshal: %v", err)
		}
	})
}

// FuzzUnmarshalGetRoot fuzzes the GetRootResponse message.
func FuzzUnmarshalGetRoot(f *testing.F) {
	zeros32 := make([]byte, 32)
	f.Add(seedBytes(f, &pb.GetRootResponse{
		Root:     zeros32,
		TreeSize: 42,
	}))
	f.Add(seedBytes(f, &pb.GetRootResponse{}))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg := &pb.GetRootResponse{}
		if err := proto.Unmarshal(data, msg); err != nil {
			return
		}
		if _, err := proto.Marshal(msg); err != nil {
			t.Errorf("round-trip marshal after successful unmarshal: %v", err)
		}
	})
}

// FuzzUnmarshalSignRoot fuzzes the SignRootResponse message, which carries
// an Ed25519 signature and public key.
func FuzzUnmarshalSignRoot(f *testing.F) {
	f.Add(seedBytes(f, &pb.SignRootResponse{
		Signature: make([]byte, 64),
		PublicKey: make([]byte, 32),
	}))
	f.Add(seedBytes(f, &pb.SignRootResponse{}))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg := &pb.SignRootResponse{}
		if err := proto.Unmarshal(data, msg); err != nil {
			return
		}
		if _, err := proto.Marshal(msg); err != nil {
			t.Errorf("round-trip marshal after successful unmarshal: %v", err)
		}
	})
}
