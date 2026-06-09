import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  apiFetch,
  getDataset,
  getPublicStats,
  getRecordProof,
  getRedactionManifest,
  issueRedaction,
  redactDocument,
  issueZkBundle,
  registerPublicUser,
  reissueKey,
  verifyAnchoredExistence,
  verifyDataset,
  verifyHash,
  verifyProofBundle,
  verifyZkProof,
} from "./api";

function jsonResponse(body: unknown, init: ResponseInit = { status: 200 }): Response {
  return new Response(JSON.stringify(body), {
    headers: { "content-type": "application/json" },
    ...init,
  });
}

function htmlResponse(status = 200): Response {
  return new Response(`<!DOCTYPE html><html></html>`, {
    status,
    headers: { "content-type": "text/html" },
  });
}

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn());
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("apiFetch", () => {
  it("returns parsed JSON on a 2xx response", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ ok: true, n: 7 }));
    const data = await apiFetch<{ ok: boolean; n: number }>("/x");
    expect(data).toEqual({ ok: true, n: 7 });
  });

  it("throws ApiError carrying status + detail on a JSON error body", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ detail: "no key" }, { status: 401 }),
    );
    await expect(apiFetch("/x")).rejects.toMatchObject({
      name: "ApiError",
      status: 401,
      detail: "no key",
    });
  });

  it("ApiError surfaces required_scope and granted_scopes from a 403 body", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(
        { detail: "needs admin", required_scope: "admin", granted_scopes: ["read"] },
        { status: 403 },
      ),
    );
    try {
      await apiFetch("/x");
      throw new Error("should have thrown");
    } catch (e) {
      const err = e as ApiError;
      expect(err).toBeInstanceOf(ApiError);
      expect(err.requiredScope).toBe("admin");
      expect(err.grantedScopes).toEqual(["read"]);
    }
  });

  it("uses json.error when json.detail is missing", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ error: "boom" }, { status: 500 }),
    );
    await expect(apiFetch("/x")).rejects.toMatchObject({ detail: "boom" });
  });

  it("returns 'Server not ready' detail when the error body is HTML (asset server)", async () => {
    vi.mocked(fetch).mockResolvedValue(htmlResponse(404));
    await expect(apiFetch("/x")).rejects.toMatchObject({
      status: 404,
      detail: expect.stringMatching(/Server not ready/),
    });
  });

  it("throws a plain Error on a 200 response with HTML body", async () => {
    vi.mocked(fetch).mockResolvedValue(htmlResponse(200));
    await expect(apiFetch("/foo")).rejects.toThrow(/Server not ready/);
  });

  it("falls back to statusText when the error body is empty", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response("", { status: 502, statusText: "Bad Gateway" }),
    );
    await expect(apiFetch("/x")).rejects.toMatchObject({ status: 502, detail: "Bad Gateway" });
  });
});

describe("simple GET wrappers", () => {
  it("verifyHash hits /ingest/records/hash/{hash}/verify with X-API-Key header", async () => {
    const fetchSpy = vi.mocked(fetch);
    fetchSpy.mockResolvedValue(jsonResponse({ ok: true }));
    await verifyHash("deadbeef", "  oly_x  ");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0];
    expect(String(url)).toMatch(/\/ingest\/records\/hash\/deadbeef\/verify$/);
    // apiKey is trimmed before being sent
    expect((init?.headers as Record<string, string>)["X-API-Key"]).toBe("oly_x");
  });

  it("verifyHash omits X-API-Key when no key is passed", async () => {
    const fetchSpy = vi.mocked(fetch);
    fetchSpy.mockResolvedValue(jsonResponse({ ok: true }));
    await verifyHash("aa");
    const [, init] = fetchSpy.mock.calls[0];
    expect((init?.headers as Record<string, string>)).not.toHaveProperty("X-API-Key");
  });

  it("getRecordProof hits /ingest/records/{proofId}", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ proof_id: "p1" }));
    await getRecordProof("p1");
    expect(String(vi.mocked(fetch).mock.calls[0][0])).toMatch(/\/ingest\/records\/p1$/);
  });

  it("getDataset hits /datasets/{id}", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ dataset_id: "d1" }));
    await getDataset("d1");
    expect(String(vi.mocked(fetch).mock.calls[0][0])).toMatch(/\/datasets\/d1$/);
  });

  it("verifyDataset hits /datasets/{id}/verify", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ verified: true }));
    await verifyDataset("d1");
    expect(String(vi.mocked(fetch).mock.calls[0][0])).toMatch(/\/datasets\/d1\/verify$/);
  });

  it("getPublicStats hits /v1/public/stats with cache:'no-store'", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ nodes: 0, shards: 0, proofs: 0, sbts_issued: 0, uptime: "0s", uptime_seconds: 0 }));
    await getPublicStats();
    const [url, init] = vi.mocked(fetch).mock.calls[0];
    expect(String(url)).toMatch(/\/v1\/public\/stats$/);
    expect(init?.cache).toBe("no-store");
  });
});

describe("POST wrappers", () => {
  it("verifyProofBundle sends a JSON body to /ingest/proofs/verify", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ status: "verified" }));
    await verifyProofBundle({
      content_hash: "ch",
      merkle_root: "root",
      merkle_proof: { siblings: [] },
    });
    const [url, init] = vi.mocked(fetch).mock.calls[0];
    expect(String(url)).toMatch(/\/ingest\/proofs\/verify$/);
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toMatchObject({ content_hash: "ch" });
  });

  it("registerPublicUser posts to /auth/register", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ user_id: "u-1", api_key: "k" }));
    await registerPublicUser({ email: "u@x.com", password: "long-enough-password" });
    const [url, init] = vi.mocked(fetch).mock.calls[0];
    expect(String(url)).toMatch(/\/auth\/register$/);
    expect(init?.method).toBe("POST");
    const body = JSON.parse(String(init?.body));
    expect(body.email).toBe("u@x.com");
  });

  it("reissueKey posts to /auth/reissue-key with the canonical scope list", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ api_key: "k", key_id: "kid", scopes: [], expires_at: "" }),
    );
    await reissueKey("u@x.com", "pw");
    const body = JSON.parse(String(vi.mocked(fetch).mock.calls[0][1]?.body));
    expect(body.scopes).toEqual(["read", "verify", "ingest", "commit", "write"]);
  });

  it("verifyZkProof posts to /zk/verify and forwards the API key header", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ valid: true, circuit: "document_existence" }));
    await verifyZkProof(
      { circuit: "document_existence", proofJson: "{}", publicSignals: ["a", "b", "c"] },
      "key-1",
    );
    const [, init] = vi.mocked(fetch).mock.calls[0];
    expect(init?.method).toBe("POST");
    expect((init?.headers as Record<string, string>)["X-API-Key"]).toBe("key-1");
  });

  it("issueZkBundle hits /ingest/records/hash/{hash}/zk_bundle", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ circuit: "document_existence", publicSignals: [], contentHash: "ch" }),
    );
    await issueZkBundle("aa", "key");
    expect(String(vi.mocked(fetch).mock.calls[0][0])).toMatch(
      /\/ingest\/records\/hash\/aa\/zk_bundle$/,
    );
  });

  it("issueRedaction POSTs /redaction/issue with object ids, recipient, and key", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ circuit: "redaction_validity", publicSignals: [], contentHash: "aa" }),
    );
    const redactedObjIds = [3, 7];
    await issueRedaction("aa", redactedObjIds, "1", "key-r");
    const [url, init] = vi.mocked(fetch).mock.calls[0];
    expect(String(url)).toMatch(/\/redaction\/issue$/);
    expect(init?.method).toBe("POST");
    expect((init?.headers as Record<string, string>)["X-API-Key"]).toBe("key-r");
    expect(JSON.parse(init?.body as string)).toEqual({
      content_hash: "aa",
      redacted_obj_ids: redactedObjIds,
      recipient_id: "1",
    });
  });

  it("getRedactionManifest GETs /redaction/manifest/{hash} with the key header", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ contentHash: "aa", originalRoot: "or", objectCount: 0, objects: [] }),
    );
    await getRedactionManifest("aa", "key-m");
    const [url, init] = vi.mocked(fetch).mock.calls[0];
    expect(String(url)).toMatch(/\/redaction\/manifest\/aa$/);
    expect((init?.headers as Record<string, string>)["X-API-Key"]).toBe("key-m");
  });

  it("redactDocument POSTs /redaction/redact with object ids", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ redactedBase64: "QUJD", bundle: {} }),
    );
    await redactDocument("Zm9v", [5], "1", "key-d");
    const [url, init] = vi.mocked(fetch).mock.calls[0];
    expect(String(url)).toMatch(/\/redaction\/redact$/);
    expect(init?.method).toBe("POST");
    expect((init?.headers as Record<string, string>)["X-API-Key"]).toBe("key-d");
    expect(JSON.parse(init?.body as string)).toEqual({
      original_base64: "Zm9v",
      redacted_obj_ids: [5],
      recipient_id: "1",
    });
  });
});

describe("verifyAnchoredExistence", () => {
  // Pre-compute the snapshot_root → BigInt decimal mapping the source uses.
  // 0x10 == decimal "16".
  const SNAPSHOT_ROOT_HEX = "10";
  const SNAPSHOT_ROOT_DEC = "16";

  it("rejects non-document_existence circuits", async () => {
    await expect(
      verifyAnchoredExistence({
        circuit: "non_existence",
        proofJson: "{}",
        publicSignals: [],
        contentHash: "ch",
      }),
    ).rejects.toThrow(/only supports document_existence/);
  });

  it("returns valid=true when math + binding + snapshot all pass", async () => {
    vi.mocked(fetch)
      // First call: verifyZkProof
      .mockResolvedValueOnce(jsonResponse({ valid: true, circuit: "document_existence" }))
      // Second: snapshot verify
      .mockResolvedValueOnce(
        jsonResponse({
          status: "verified",
          detail: "ok",
          snapshot_root: SNAPSHOT_ROOT_HEX,
          snapshot_index: 3,
          snapshot_size: 8,
        }),
      );

    const out = await verifyAnchoredExistence({
      circuit: "document_existence",
      proofJson: "{}",
      publicSignals: [SNAPSHOT_ROOT_DEC, "3", "8"],
      contentHash: "ch",
    });
    expect(out).toMatchObject({
      valid: true,
      proofMathValid: true,
      signalsBindToSnapshot: true,
      snapshotTrusted: true,
    });
    expect(out.detail).toMatch(/Proof math, signal binding/);
  });

  it("returns valid=false when proof math fails", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse({ valid: false, circuit: "document_existence" }))
      .mockResolvedValueOnce(
        jsonResponse({
          status: "verified",
          detail: "ok",
          snapshot_root: SNAPSHOT_ROOT_HEX,
          snapshot_index: 3,
          snapshot_size: 8,
        }),
      );

    const out = await verifyAnchoredExistence({
      circuit: "document_existence",
      proofJson: "{}",
      publicSignals: [SNAPSHOT_ROOT_DEC, "3", "8"],
      contentHash: "ch",
    });
    expect(out.valid).toBe(false);
    expect(out.proofMathValid).toBe(false);
    expect(out.detail).toMatch(/proof math invalid/);
  });

  it("returns valid=false when public signals do not match the server snapshot", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse({ valid: true, circuit: "document_existence" }))
      .mockResolvedValueOnce(
        jsonResponse({
          status: "verified",
          detail: "ok",
          snapshot_root: SNAPSHOT_ROOT_HEX,
          snapshot_index: 3,
          snapshot_size: 8,
        }),
      );

    const out = await verifyAnchoredExistence({
      circuit: "document_existence",
      proofJson: "{}",
      // Wrong leafIndex
      publicSignals: [SNAPSHOT_ROOT_DEC, "999", "8"],
      contentHash: "ch",
    });
    expect(out.signalsBindToSnapshot).toBe(false);
    expect(out.valid).toBe(false);
  });

  it("returns valid=false when the snapshot is not 'verified'", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse({ valid: true, circuit: "document_existence" }))
      .mockResolvedValueOnce(
        jsonResponse({
          status: "pending",
          detail: "no snapshot anchored yet",
          snapshot_root: SNAPSHOT_ROOT_HEX,
          snapshot_index: 3,
          snapshot_size: 8,
        }),
      );

    const out = await verifyAnchoredExistence({
      circuit: "document_existence",
      proofJson: "{}",
      publicSignals: [SNAPSHOT_ROOT_DEC, "3", "8"],
      contentHash: "ch",
    });
    expect(out.snapshotTrusted).toBe(false);
    expect(out.detail).toMatch(/snapshot pending/);
  });

  it("flags a bundle whose own claimed snapshotRoot disagrees with the public signals", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse({ valid: true, circuit: "document_existence" }))
      .mockResolvedValueOnce(
        jsonResponse({
          status: "verified",
          detail: "ok",
          snapshot_root: SNAPSHOT_ROOT_HEX,
          snapshot_index: 3,
          snapshot_size: 8,
        }),
      );

    const out = await verifyAnchoredExistence({
      circuit: "document_existence",
      proofJson: "{}",
      publicSignals: [SNAPSHOT_ROOT_DEC, "3", "8"],
      contentHash: "ch",
      // Different from public signal — tamper sentinel
      snapshotRoot: "1f",
    });
    expect(out.signalsBindToSnapshot).toBe(false);
    expect(out.valid).toBe(false);
  });
});
