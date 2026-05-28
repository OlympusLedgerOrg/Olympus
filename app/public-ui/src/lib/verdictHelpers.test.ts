import { describe, expect, it } from "vitest";
import { hashVerificationToVerdict, proofVerificationToVerdict } from "./verdictHelpers";
import type { HashVerificationResponse, ProofVerificationResponse } from "./types";

const baseHash: HashVerificationResponse = {
  content_hash: "ch",
  proof_id: "pid",
  record_id: "rid",
  shard_id: "7",
  merkle_root: "root",
  merkle_proof: null,
  merkle_proof_valid: true,
  ledger_entry_hash: "leh",
  timestamp: "2026-05-28T00:00:00Z",
};

describe("hashVerificationToVerdict", () => {
  it("maps merkle_proof_valid=true to verdict='verified'", () => {
    const r = hashVerificationToVerdict(baseHash);
    expect(r.verdict).toBe("verified");
    expect(r.details.find((d) => d.key === "Merkle Proof")?.status).toBe("ok");
  });

  it("maps merkle_proof_valid=false to verdict='failed'", () => {
    const r = hashVerificationToVerdict({ ...baseHash, merkle_proof_valid: false });
    expect(r.verdict).toBe("failed");
    expect(r.details.find((d) => d.key === "Merkle Proof")?.status).toBe("err");
  });

  it("appends a poseidon_root row when present", () => {
    const r = hashVerificationToVerdict({ ...baseHash, poseidon_root: "pr" });
    expect(r.details.find((d) => d.key === "Poseidon Root")?.value).toBe("pr");
  });

  it("omits the poseidon_root row when absent", () => {
    const r = hashVerificationToVerdict(baseHash);
    expect(r.details.find((d) => d.key === "Poseidon Root")).toBeUndefined();
  });

  it("formats the timestamp as a locale string", () => {
    const r = hashVerificationToVerdict(baseHash);
    const ts = r.details.find((d) => d.key === "Committed")?.value;
    expect(ts).not.toBe(baseHash.timestamp);
    expect(typeof ts).toBe("string");
  });
});

describe("proofVerificationToVerdict", () => {
  const make = (
    status: ProofVerificationResponse["status"],
    extra: Partial<ProofVerificationResponse> = {},
  ): ProofVerificationResponse => ({
    content_hash: "ch",
    status,
    detail: "info",
    known_to_server: true,
    snapshot_root: null,
    snapshot_index: null,
    snapshot_size: null,
    merkle_proof_valid: null,
    merkle_root: "",
    ...extra,
  });

  it("status=verified → verified verdict + ok snapshot status", () => {
    const r = proofVerificationToVerdict(make("verified"));
    expect(r.verdict).toBe("verified");
    expect(r.details.find((d) => d.key === "Snapshot Status")?.status).toBe("ok");
  });

  it("status=invalid → failed verdict + err snapshot status", () => {
    const r = proofVerificationToVerdict(make("invalid"));
    expect(r.verdict).toBe("failed");
    expect(r.details.find((d) => d.key === "Snapshot Status")?.status).toBe("err");
  });

  it("status=pending → unknown verdict + warn snapshot status (not a rejection)", () => {
    const r = proofVerificationToVerdict(make("pending"));
    expect(r.verdict).toBe("unknown");
    expect(r.details.find((d) => d.key === "Snapshot Status")?.status).toBe("warn");
  });

  it("status=unknown → unknown verdict + err snapshot status", () => {
    const r = proofVerificationToVerdict(make("unknown"));
    expect(r.verdict).toBe("unknown");
    expect(r.details.find((d) => d.key === "Snapshot Status")?.status).toBe("err");
  });

  it("appends Snapshot Root when present", () => {
    const r = proofVerificationToVerdict(make("verified", { snapshot_root: "sr" }));
    expect(r.details.find((d) => d.key === "Snapshot Root")?.value).toBe("sr");
  });

  it("known_to_server=false maps to warn status on 'Known to Server' row", () => {
    const r = proofVerificationToVerdict(make("unknown", { known_to_server: false }));
    expect(r.details.find((d) => d.key === "Known to Server")?.status).toBe("warn");
  });
});
