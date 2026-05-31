import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  verifyZkProof: vi.fn(),
  verifyAnchoredExistence: vi.fn(),
}));
vi.mock("../lib/storage", () => ({
  getStoredApiKey: vi.fn(() => ""),
}));

import { verifyAnchoredExistence, verifyZkProof } from "../lib/api";
import { getStoredApiKey } from "../lib/storage";
import { useAuditProof } from "./useAuditProof";

const mockedVerifyZkProof = vi.mocked(verifyZkProof);
const mockedVerifyAnchored = vi.mocked(verifyAnchoredExistence);
const mockedGetStoredApiKey = vi.mocked(getStoredApiKey);

const PROOF_JSON_OBJ = { pi_a: ["1"], pi_b: [["2"]], pi_c: ["3"] };

beforeEach(() => {
  mockedVerifyZkProof.mockReset();
  mockedVerifyAnchored.mockReset();
  mockedGetStoredApiKey.mockReturnValue("");
});

afterEach(() => {
  vi.restoreAllMocks();
});

function asFile(obj: unknown, name = "bundle.json"): File {
  return new File([JSON.stringify(obj)], name, { type: "application/json" });
}

describe("useAuditProof", () => {
  it("starts in idle state with everything null", () => {
    const { result } = renderHook(() => useAuditProof());
    expect(result.current.stage).toBe("idle");
    expect(result.current.parsed).toBeNull();
    expect(result.current.result).toBeNull();
    expect(result.current.anchor).toBeNull();
    expect(result.current.error).toBeNull();
  });

  it("onBundleFile parses snake_case keys and transitions to 'ready'", async () => {
    const { result } = renderHook(() => useAuditProof());
    await act(async () => {
      await result.current.onBundleFile(
        asFile({
          circuit: "document_existence",
          proof_json: PROOF_JSON_OBJ,
          public_signals: ["1", "2", "3", "4"],
        }),
      );
    });
    expect(result.current.stage).toBe("ready");
    expect(result.current.bundleName).toBe("bundle.json");
    expect(result.current.parsed?.circuit).toBe("document_existence");
    expect(result.current.parsed?.publicSignals).toEqual(["1", "2", "3", "4"]);
    // proof object is re-serialised
    expect(JSON.parse(result.current.parsed!.proofJson)).toEqual(PROOF_JSON_OBJ);
  });

  it("onBundleFile parses camelCase keys (snarkjs raw output)", async () => {
    const { result } = renderHook(() => useAuditProof());
    await act(async () => {
      await result.current.onBundleFile(
        asFile({
          circuit: "non_existence",
          proofJson: '{"pi_a":["1"]}',
          publicSignals: ["a", "b"],
        }),
      );
    });
    expect(result.current.stage).toBe("ready");
    expect(result.current.parsed?.circuit).toBe("non_existence");
  });

  it("captures anchoring metadata fields when present", async () => {
    const { result } = renderHook(() => useAuditProof());
    await act(async () => {
      await result.current.onBundleFile(
        asFile({
          circuit: "document_existence",
          proof_json: PROOF_JSON_OBJ,
          public_signals: ["1", "2", "3", "4"],
          content_hash: "ch-aaa",
          snapshot_root: "sr-bbb",
          snapshot_index: 7,
          snapshot_size: 16,
        }),
      );
    });
    expect(result.current.parsed?.contentHash).toBe("ch-aaa");
    expect(result.current.parsed?.snapshotRoot).toBe("sr-bbb");
    expect(result.current.parsed?.snapshotIndex).toBe(7);
    expect(result.current.parsed?.snapshotSize).toBe(16);
  });

  it("rejects an unknown circuit name with a clear error", async () => {
    const { result } = renderHook(() => useAuditProof());
    await act(async () => {
      await result.current.onBundleFile(
        asFile({ circuit: "made_up_circuit", proof_json: "{}", public_signals: [] }),
      );
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/unknown circuit/i);
  });

  it("rejects a bundle missing proof_json with a clear error", async () => {
    const { result } = renderHook(() => useAuditProof());
    await act(async () => {
      await result.current.onBundleFile(
        asFile({ circuit: "document_existence", public_signals: [] }),
      );
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/proof_json/);
  });

  it("rejects a bundle whose public_signals is not an array", async () => {
    const { result } = renderHook(() => useAuditProof());
    await act(async () => {
      await result.current.onBundleFile(
        asFile({ circuit: "document_existence", proof_json: "{}", public_signals: "nope" }),
      );
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/public_signals/);
  });

  it("onBundleText empty input resets state to INITIAL", () => {
    const { result } = renderHook(() => useAuditProof());
    act(() => result.current.onBundleText("   "));
    expect(result.current.stage).toBe("idle");
    expect(result.current.parsed).toBeNull();
  });

  it("onBundleText parses a JSON string paste", () => {
    const { result } = renderHook(() => useAuditProof());
    act(() =>
      result.current.onBundleText(
        JSON.stringify({
          circuit: "redaction_validity",
          proof_json: "{}",
          public_signals: ["1", "2", "3", "4", "5", "6"],
        }),
      ),
    );
    expect(result.current.stage).toBe("ready");
    expect(result.current.parsed?.circuit).toBe("redaction_validity");
  });

  it("onBundleText surfaces an error on malformed JSON", () => {
    const { result } = renderHook(() => useAuditProof());
    act(() => result.current.onBundleText("not-json"));
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toBeTruthy();
  });

  it("audit short-circuits when no parsed bundle is loaded", async () => {
    const { result } = renderHook(() => useAuditProof());
    await act(async () => {
      await result.current.audit();
    });
    expect(mockedVerifyZkProof).not.toHaveBeenCalled();
    expect(result.current.stage).toBe("idle");
  });

  it("audit happy path: non_existence runs verifyZkProof, skips anchored verify", async () => {
    mockedVerifyZkProof.mockResolvedValue({ valid: true, circuit: "non_existence" });
    const { result } = renderHook(() => useAuditProof());
    act(() =>
      result.current.onBundleText(
        JSON.stringify({
          circuit: "non_existence",
          proof_json: "{}",
          public_signals: ["a", "b"],
        }),
      ),
    );
    await act(async () => {
      await result.current.audit();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    expect(result.current.result).toEqual({ valid: true, circuit: "non_existence" });
    expect(result.current.anchor).toBeNull();
    expect(mockedVerifyAnchored).not.toHaveBeenCalled();
  });

  it("audit runs anchored verify on document_existence when content_hash is present", async () => {
    mockedVerifyZkProof.mockResolvedValue({ valid: true, circuit: "document_existence" });
    mockedVerifyAnchored.mockResolvedValue({
      valid: true,
      proofMathValid: true,
      signalsBindToSnapshot: true,
      snapshotTrusted: true,
      detail: "ok",
    });
    const { result } = renderHook(() => useAuditProof());
    act(() =>
      result.current.onBundleText(
        JSON.stringify({
          circuit: "document_existence",
          proof_json: "{}",
          public_signals: ["1", "2", "3", "4"],
          content_hash: "ch",
          snapshot_root: "sr",
          snapshot_index: 0,
          snapshot_size: 1,
        }),
      ),
    );
    await act(async () => {
      await result.current.audit();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    expect(mockedVerifyAnchored).toHaveBeenCalled();
    expect(result.current.anchor?.valid).toBe(true);
  });

  it("audit skips anchored verify when document_existence has no content_hash", async () => {
    mockedVerifyZkProof.mockResolvedValue({ valid: true, circuit: "document_existence" });
    const { result } = renderHook(() => useAuditProof());
    act(() =>
      result.current.onBundleText(
        JSON.stringify({
          circuit: "document_existence",
          proof_json: "{}",
          public_signals: ["1", "2", "3", "4"],
        }),
      ),
    );
    await act(async () => {
      await result.current.audit();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    expect(mockedVerifyAnchored).not.toHaveBeenCalled();
    expect(result.current.anchor).toBeNull();
  });

  it("anchored verify failure is captured as anchor.valid=false (does NOT abort)", async () => {
    mockedVerifyZkProof.mockResolvedValue({ valid: true, circuit: "document_existence" });
    mockedVerifyAnchored.mockRejectedValue(new Error("snapshot endpoint 503"));
    const { result } = renderHook(() => useAuditProof());
    act(() =>
      result.current.onBundleText(
        JSON.stringify({
          circuit: "document_existence",
          proof_json: "{}",
          public_signals: ["1", "2", "3", "4"],
          content_hash: "ch",
        }),
      ),
    );
    await act(async () => {
      await result.current.audit();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    // Proof math succeeded; anchor synthesises a failed result with the err message.
    expect(result.current.result?.valid).toBe(true);
    expect(result.current.anchor?.valid).toBe(false);
    expect(result.current.anchor?.detail).toMatch(/snapshot endpoint 503/);
  });

  it("audit error from verifyZkProof lands in 'error' stage", async () => {
    mockedVerifyZkProof.mockRejectedValue(new Error("zk verify rejected"));
    const { result } = renderHook(() => useAuditProof());
    act(() =>
      result.current.onBundleText(
        JSON.stringify({
          circuit: "non_existence",
          proof_json: "{}",
          public_signals: ["a", "b"],
        }),
      ),
    );
    await act(async () => {
      await result.current.audit();
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/zk verify rejected/);
  });

  it("forwards the stored API key to verifyZkProof", async () => {
    mockedGetStoredApiKey.mockReturnValue("oly_stored");
    mockedVerifyZkProof.mockResolvedValue({ valid: false, circuit: "non_existence" });
    const { result } = renderHook(() => useAuditProof());
    act(() =>
      result.current.onBundleText(
        JSON.stringify({
          circuit: "non_existence",
          proof_json: "{}",
          public_signals: ["a", "b"],
        }),
      ),
    );
    await act(async () => {
      await result.current.audit();
    });
    expect(mockedVerifyZkProof).toHaveBeenCalledWith(expect.any(Object), "oly_stored");
  });

  it("reset returns to the initial state", () => {
    const { result } = renderHook(() => useAuditProof());
    act(() =>
      result.current.onBundleText(
        JSON.stringify({
          circuit: "non_existence",
          proof_json: "{}",
          public_signals: ["a", "b"],
        }),
      ),
    );
    act(() => result.current.reset());
    expect(result.current.stage).toBe("idle");
    expect(result.current.parsed).toBeNull();
  });
});
