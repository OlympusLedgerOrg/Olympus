package verifier

import (
"crypto/ed25519"
"encoding/hex"
"encoding/json"
"fmt"
)

type witnessCosignature struct {
WitnessID    string `json:"witness_id"`
PublicKeyHex string `json:"public_key_hex"`
SignatureHex string `json:"signature_hex"`
}

type witnessEnvelope struct {
RootHash          string               `json:"root_hash"`
WitnessThreshold  int                  `json:"witness_threshold"`
WitnessCosignatures []witnessCosignature `json:"witness_cosignatures"`
}

func VerifyWitnessEnvelopeJSON(raw []byte) error {
var env witnessEnvelope
if err := json.Unmarshal(raw, &env); err != nil {
return err
}
root, err := hex.DecodeString(env.RootHash)
if err != nil || len(root) != 32 {
return fmt.Errorf("invalid root hash")
}
payload := append([]byte("OLY:WITNESS:V1|"), root...)
valid := map[string]struct{}{}
for _, c := range env.WitnessCosignatures {
pk, err := hex.DecodeString(c.PublicKeyHex)
if err != nil || len(pk) != ed25519.PublicKeySize {
continue
}
sig, err := hex.DecodeString(c.SignatureHex)
if err != nil || len(sig) != ed25519.SignatureSize {
continue
}
if ed25519.Verify(ed25519.PublicKey(pk), payload, sig) {
valid[c.WitnessID] = struct{}{}
}
}
if len(valid) < env.WitnessThreshold {
return fmt.Errorf("threshold not met")
}
return nil
}
