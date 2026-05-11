package api

import (
	"context"
	"errors"
	"testing"

	pb "github.com/OlympusLedgerOrg/Olympus/services/sequencer/proto"
)

// witnessOnlySMT is a minimal smtBackend stub for witness cosigning tests.
// It is distinct from fakeSMT (defined in sequencer_atomicity_test.go) to
// avoid duplicate type declarations within the same test package.
type witnessOnlySMT struct {
	sig []byte
	err error
}

func (f *witnessOnlySMT) Canonicalize(context.Context, string, []byte) (*pb.CanonicalizeResponse, error) {
	return nil, nil
}
func (f *witnessOnlySMT) PrepareUpdate(context.Context, string, *pb.RecordKey, []byte, []byte, string, string) (*pb.PrepareUpdateResponse, error) {
	return nil, nil
}
func (f *witnessOnlySMT) CommitPreparedUpdate(context.Context, string) (*pb.CommitPreparedUpdateResponse, error) {
	return nil, nil
}
func (f *witnessOnlySMT) AbortPreparedUpdate(context.Context, string) error { return nil }
func (f *witnessOnlySMT) ProveInclusion(context.Context, string, *pb.RecordKey, []byte) (*pb.ProveInclusionResponse, error) {
	return nil, nil
}
func (f *witnessOnlySMT) SignRoot(context.Context, []byte, uint64, map[string]string) (*pb.SignRootResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &pb.SignRootResponse{Signature: f.sig}, nil
}

type fakeWitness struct {
	url string
}

func (f fakeWitness) URL() string { return f.url }
func (f fakeWitness) CosignRoot(_ context.Context, _ [32]byte, _ uint64, _ []byte) (WitnessCosignature, error) {
	return WitnessCosignature{WitnessID: "w1", Signature: []byte{1, 2, 3}}, nil
}

func TestValidateWitnessURLRejectsSSRFHosts(t *testing.T) {
	cases := []string{
		"http://localhost:9000",
		"http://127.0.0.1:9000",
		"http://10.0.0.4:9000",
		"file:///tmp/witness",
	}
	for _, candidate := range cases {
		if err := validateWitnessURL(candidate); err == nil {
			t.Fatalf("expected URL %q to be rejected", candidate)
		}
	}
}

func TestSignAndCosignRootScaffold(t *testing.T) {
	s := &Sequencer{
		smtClient:      &witnessOnlySMT{sig: []byte{9, 9, 9}},
		witnessClients: []WitnessClient{fakeWitness{url: "https://203.0.113.1"}},
	}
	root := [32]byte{7}
	envelope, err := s.SignAndCosignRoot(context.Background(), root)
	if err != nil {
		t.Fatalf("expected success, got err=%v", err)
	}
	if len(envelope.SequencerSignature) == 0 {
		t.Fatal("expected sequencer signature")
	}
	if len(envelope.WitnessCosignatures) != 1 {
		t.Fatalf("expected 1 witness cosig, got %d", len(envelope.WitnessCosignatures))
	}
}

func TestSignAndCosignRootFailsOnSignError(t *testing.T) {
	s := &Sequencer{smtClient: &witnessOnlySMT{err: errors.New("boom")}}
	_, err := s.SignAndCosignRoot(context.Background(), [32]byte{1})
	if err == nil {
		t.Fatal("expected error")
	}
}
