import { readFileSync } from 'node:fs';
import { verify } from 'node:crypto';

export function verifyWitnessEnvelope(path) {
  const env = JSON.parse(readFileSync(path, 'utf8'));
  const root = Buffer.from(env.root_hash, 'hex');
  if (root.length !== 32) {
    return false;
  }
  const payload = Buffer.concat([Buffer.from('OLY:WITNESS:V1|', 'utf8'), root]);
  const valid = new Set();
  for (const c of env.witness_cosignatures ?? []) {
    try {
      const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
      const publicKey = Buffer.concat([spkiPrefix, Buffer.from(c.public_key_hex, 'hex')]);
      const sig = Buffer.from(c.signature_hex, 'hex');
      if (verify(null, payload, { key: publicKey, format: 'der', type: 'spki' }, sig)) {
        valid.add(c.witness_id);
      }
    } catch {
      // ignore malformed signature rows in scaffold verifier
    }
  }
  return valid.size >= Number(env.witness_threshold ?? 2);
}

if (process.argv[1] && process.argv[1].endsWith('witness_cosignature.mjs')) {
  const ok = verifyWitnessEnvelope(process.argv[2]);
  process.exit(ok ? 0 : 1);
}
