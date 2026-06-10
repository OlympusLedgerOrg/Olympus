import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/blake3", () => ({
  hashFile: vi.fn(),
}));
vi.mock("../lib/api", () => ({
  verifyZkProof: vi.fn(),
}));
vi.mock("../lib/storage", () => ({
  getStoredApiKey: vi.fn(() => ""),
}));
vi.mock("../lib/redactionBinding", () => ({
  verifyRedactionBindingJs: vi.fn(),
}));

import { hashFile } from "../lib/blake3";
import { verifyZkProof } from "../lib/api";
import { verifyRedactionBindingJs } from "../lib/redactionBinding";
import { useRedactionAudit } from "./useRedactionAudit";

const mockedHashFile = vi.mocked(hashFile);
const mockedVerifyZkProof = vi.mocked(verifyZkProof);
const mockedVerifyJs = vi.mocked(verifyRedactionBindingJs);

function makeFile(name = "redacted.pdf", content = "data") {
  return new File([content], name, { type: "application/pdf" });
}

function makeBundleFile(
  overrides: Record<string, unknown> = {},
  name = "bundle.json",
) {
  const bundle = {
    circuit: "redaction_validity",
    proof_json: { pi_a: ["1"], pi_b: [["2"]], pi_c: ["3"] },
    // ADR-0026 audit-M2 public signals:
    //   [nullifier, originalRoot, redactedCommitment, revealedCount, issuerAx, issuerAy]
    public_signals: ["1", "2", "3", "4", "5", "6"],
    redacted_obj_ids: [12, 47],
    revealed_segments: [
      { segment_id: 1, blinding_decimal: "11" },
      { segment_id: 2, blinding_decimal: "22" },
    ],
    ...overrides,
  };
  return new File([JSON.stringify(bundle)], name, { type: "application/json" });
}

beforeEach(() => {
  mockedHashFile.mockReset();
  mockedHashFile.mockResolvedValue("ff".repeat(32));
  mockedVerifyZkProof.mockReset();
  mockedVerifyJs.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("useRedactionAudit", () => {
  it("starts in idle state with everything null/empty", () => {
    const { result } = renderHook(() => useRedactionAudit());
    expect(result.current.stage).toBe("idle");
    expect(result.current.fileName).toBeNull();
    expect(result.current.fileHash).toBeNull();
    expect(result.current.fileProgress).toBe(0);
    expect(result.current.bundleName).toBeNull();
    expect(result.current.parsed).toBeNull();
    expect(result.current.result).toBeNull();
    expect(result.current.bindingValid).toBeNull();
    expect(result.current.error).toBeNull();
  });

  it("onFile transitions through hashing → ready when the bundle is also loaded", async () => {
    const { result } = renderHook(() => useRedactionAudit());
    // Bundle first, then file → ready
    await act(async () => {
      await result.current.onBundleFile(makeBundleFile());
    });
    expect(result.current.stage).toBe("idle"); // no file yet
    await act(async () => {
      await result.current.onFile(makeFile());
    });
    expect(result.current.stage).toBe("ready");
    expect(result.current.fileHash).toBe("ff".repeat(32));
    expect(result.current.parsed?.circuit).toBe("redaction_validity");
    expect(result.current.parsed?.publicSignals).toHaveLength(6);
    expect(result.current.parsed?.redactedObjIds).toEqual([12, 47]);
    expect(result.current.parsed?.revealedSegments).toHaveLength(2);
    expect(result.current.parsed?.revealedSegments[0]).toEqual({
      segmentId: 1,
      blindingDecimal: "11",
    });
  });

  it("rejects bundles for the wrong circuit", async () => {
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onBundleFile(
        makeBundleFile({ circuit: "document_existence" }),
      );
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/redaction_validity/);
  });

  it("rejects bundles missing proof_json", async () => {
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onBundleFile(makeBundleFile({ proof_json: undefined }));
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/proof_json/);
  });

  it("rejects bundles whose public_signals length is not 6 (ADR-0026)", async () => {
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onBundleFile(
        makeBundleFile({ public_signals: ["1", "2", "3", "4"] }),
      );
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/6 public signals/);
  });

  it("rejects bundles missing redacted_obj_ids", async () => {
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onBundleFile(
        makeBundleFile({ redacted_obj_ids: undefined }),
      );
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/redacted_obj_ids/);
  });

  it("rejects bundles missing revealed_segments", async () => {
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onBundleFile(
        makeBundleFile({ revealed_segments: undefined }),
      );
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/revealed_segments/);
  });

  it("rejects revealed_segments entries with non-string blinding", async () => {
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onBundleFile(
        makeBundleFile({
          revealed_segments: [{ segment_id: 1, blinding_decimal: 11 as unknown as string }],
        }),
      );
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/blinding_decimal/);
  });

  it("audit short-circuits when no bundle is loaded", async () => {
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.audit();
    });
    expect(mockedVerifyZkProof).not.toHaveBeenCalled();
    expect(result.current.stage).toBe("idle");
  });

  it("audit happy path: proof valid + binding valid → stage=done, bindingValid=true", async () => {
    mockedVerifyZkProof.mockResolvedValue({ valid: true, circuit: "redaction_validity" });
    mockedVerifyJs.mockResolvedValue(true);
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onFile(makeFile());
    });
    await act(async () => {
      await result.current.onBundleFile(makeBundleFile());
    });
    await act(async () => {
      await result.current.audit();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    expect(result.current.result?.valid).toBe(true);
    expect(result.current.bindingValid).toBe(true);
    expect(mockedVerifyJs).toHaveBeenCalled();
  });

  it("audit: proof valid + binding INVALID → done, bindingValid=false", async () => {
    mockedVerifyZkProof.mockResolvedValue({ valid: true, circuit: "redaction_validity" });
    mockedVerifyJs.mockResolvedValue(false);
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onFile(makeFile());
    });
    await act(async () => {
      await result.current.onBundleFile(makeBundleFile());
    });
    await act(async () => {
      await result.current.audit();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    expect(result.current.bindingValid).toBe(false);
  });

  it("audit: proof INVALID → skips binding check (bindingValid stays null)", async () => {
    mockedVerifyZkProof.mockResolvedValue({ valid: false, circuit: "redaction_validity" });
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onFile(makeFile());
    });
    await act(async () => {
      await result.current.onBundleFile(makeBundleFile());
    });
    await act(async () => {
      await result.current.audit();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    expect(result.current.result?.valid).toBe(false);
    expect(result.current.bindingValid).toBeNull();
    expect(mockedVerifyJs).not.toHaveBeenCalled();
  });

  it("audit: verifyZkProof rejects → stage=error with the error message", async () => {
    mockedVerifyZkProof.mockRejectedValue(new Error("zk verify rejected"));
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onFile(makeFile());
    });
    await act(async () => {
      await result.current.onBundleFile(makeBundleFile());
    });
    await act(async () => {
      await result.current.audit();
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/zk verify rejected/);
  });

  it("audit: binding throws → done with bindingValid=null + error message", async () => {
    mockedVerifyZkProof.mockResolvedValue({ valid: true, circuit: "redaction_validity" });
    mockedVerifyJs.mockRejectedValue(new Error("binding compute failed"));
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onFile(makeFile());
    });
    await act(async () => {
      await result.current.onBundleFile(makeBundleFile());
    });
    await act(async () => {
      await result.current.audit();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    // Proof math succeeded; the binding throw is surfaced on `error`.
    expect(result.current.result?.valid).toBe(true);
    expect(result.current.error).toMatch(/binding compute failed/);
  });

  it("reset clears file + bundle + verdict state", async () => {
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onFile(makeFile());
    });
    await act(async () => {
      await result.current.onBundleFile(makeBundleFile());
    });
    act(() => result.current.reset());
    expect(result.current.stage).toBe("idle");
    expect(result.current.parsed).toBeNull();
    expect(result.current.fileHash).toBeNull();
    expect(result.current.bundleName).toBeNull();
  });

  it("a new file selection clears the previous audit verdict (stale-result protection)", async () => {
    mockedVerifyZkProof.mockResolvedValue({ valid: true, circuit: "redaction_validity" });
    mockedVerifyJs.mockResolvedValue(true);
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onFile(makeFile("first.pdf"));
    });
    await act(async () => {
      await result.current.onBundleFile(makeBundleFile());
    });
    await act(async () => {
      await result.current.audit();
    });
    expect(result.current.result?.valid).toBe(true);

    // New file dropped — the prior verdict must be cleared.
    await act(async () => {
      await result.current.onFile(makeFile("second.pdf"));
    });
    expect(result.current.result).toBeNull();
    expect(result.current.bindingValid).toBeNull();
  });
});
