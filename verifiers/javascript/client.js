/**
 * Lightweight REST client for Olympus ingest and proof verification workflows.
 */

const { computeBlake3, toHex } = require('./verifier');

class OlympusClient {
  /**
   * @param {{baseUrl?: string, apiKey?: string, fetchImpl?: typeof fetch}} [options]
   */
  constructor(options = {}) {
    this.baseUrl = (options.baseUrl || 'http://127.0.0.1:8000').replace(/\/$/, '');
    this.apiKey = options.apiKey || '';
    this.fetchImpl = options.fetchImpl || globalThis.fetch;
    if (!this.fetchImpl) {
      throw new Error('OlympusClient requires fetch support');
    }
  }

  _headers() {
    const headers = { 'Content-Type': 'application/json' };
    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }
    return headers;
  }

  async _request(path, { method = 'GET', body } = {}) {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers: this._headers(),
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) {
      throw new Error(`Olympus API returned HTTP ${response.status}`);
    }
    return response.json();
  }

  async commitArtifact({ artifactHash, namespace, id, poseidonRoot }) {
    return this._request('/ingest/commit', {
      method: 'POST',
      body: {
        artifact_hash: artifactHash,
        namespace,
        id,
        poseidon_root: poseidonRoot || null,
      },
    });
  }

  async getProof(proofId) {
    return this._request(`/ingest/records/${proofId}/proof`);
  }

  async verifyContentHash(contentHash) {
    return this._request(`/ingest/records/hash/${contentHash}/verify`);
  }

  async verifyProofBundle(bundle) {
    return this._request('/ingest/proofs/verify', {
      method: 'POST',
      body: {
        proof_id: bundle.proof_id || null,
        content_hash: bundle.content_hash,
        merkle_root: bundle.merkle_root,
        merkle_proof: bundle.merkle_proof,
        poseidon_root: bundle.poseidon_root || null,
      },
    });
  }

  async submitProofBundle(bundle) {
    return this._request('/ingest/proofs', {
      method: 'POST',
      body: bundle,
    });
  }

  async ingestFile({
    fileBytes,
    namespace = 'demo',
    id = 'artifact',
    poseidonRoot = null,
    generateProof = false,
    verify = false,
  }) {
    const artifactHash = toHex(computeBlake3(new Uint8Array(fileBytes)));
    const commit = await this.commitArtifact({ artifactHash, namespace, id, poseidonRoot });
    const result = { artifactHash, commit };
    if (generateProof) {
      result.proof = await this.getProof(commit.proof_id);
    }
    if (verify) {
      result.verification = await this.verifyContentHash(artifactHash);
    }
    return result;
  }
}

module.exports = {
  OlympusClient,
};
