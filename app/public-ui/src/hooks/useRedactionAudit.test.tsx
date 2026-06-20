import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/blake3", () => ({
  hashFile: vi.fn(),
}));
vi.mock("../lib/redactionBinding", () => ({
  verifyRedactionBundleV3: vi.fn(),
}));
vi.mock("../lib/api", () => ({
  getRedactionIssuerKey: vi.fn(),
}));

import { hashFile } from "../lib/blake3";
import { verifyRedactionBundleV3 } from "../lib/redactionBinding";
import { getRedactionIssuerKey } from "../lib/api";
import { useRedactionAudit } from "./useRedactionAudit";

const mockedHashFile = vi.mocked(hashFile);
const mockedVerify = vi.mocked(verifyRedactionBundleV3);
const mockedIssuerKey = vi.mocked(getRedactionIssuerKey);

const ISSUER = "aa".repeat(32);

function makeFile(name = "redacted.txt", content = "data") {
  return new File([content], name, { type: "text/plain" });
}

function v3Bundle(overrides: Record<string, unknown> = {}) {
  return {
    original_root: "ab".repeat(32),
    format: "text-line",
    segment_count: 2,
    recipient_id: "12345",
    segments: [
      { segment_id: 0, redacted: false, artifact_offset: 0, artifact_length: 4, blinding_decimal: "7" },
      { segment_id: 1, redacted: true, artifact_offset: 4, artifact_length: 0, leaf_hex: "cd".repeat(32) },
    ],
    nullifier: "ef".repeat(32),
    signature_hex: "00".repeat(64),
    ...overrides,
  };
}

function makeBundleFile(overrides: Record<string, unknown> = {}, name = "bundle.json") {
  return new File([JSON.stringify(v3Bundle(overrides))], name, { type: "application/json" });
}

beforeEach(() => {
  mockedHashFile.mockReset();
  mockedHashFile.mockResolvedValue("ff".repeat(32));
  mockedVerify.mockReset();
  mockedVerify.mockReturnValue({ ok: true });
  // Default: no issuer key published, so the mount-time auto-fill is a no-op
  // and the issuer field stays empty for the existing assertions.
  mockedIssuerKey.mockReset();
  mockedIssuerKey.mockRejectedValue(new Error("no issuer key"));
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
    expect(result.current.bundleName).toBeNull();
    expect(result.current.parsed).toBeNull();
    expect(result.current.issuerPubkeyHex).toBe("");
    expect(result.current.issuerKeyAutofilled).toBe(false);
    expect(result.current.verified).toBeNull();
    expect(result.current.error).toBeNull();
  });

  it("auto-fills the issuer key from the instance on mount", async () => {
    mockedIssuerKey.mockReset();
    mockedIssuerKey.mockResolvedValue({ ed25519PubkeyHex: ISSUER });
    const { result } = renderHook(() => useRedactionAudit());
    await waitFor(() => {
      expect(result.current.issuerPubkeyHex).toBe(ISSUER);
    });
    expect(result.current.issuerKeyAutofilled).toBe(true);
  });

  it("does not clobber a user-supplied key that arrives before the auto-fill", async () => {
    // Issuer-key fetch resolves with a different value after user input.
    let resolveIssuerKey: (value: { ed25519PubkeyHex: string }) => void;
    mockedIssuerKey.mockReset();
    mockedIssuerKey.mockReturnValue(
      new Promise((resolve) => {
        resolveIssuerKey = resolve;
      }),
    );
    const { result } = renderHook(() => useRedactionAudit());
    act(() => {
      result.current.setIssuerPubkey("bb".repeat(32));
    });
    // Now resolve the auto-fill with a different issuer key
    act(() => {
      resolveIssuerKey({ ed25519PubkeyHex: "cc".repeat(32) });
    });
    await waitFor(() => {
      // User-supplied value should not be clobbered by the delayed auto-fill
      expect(result.current.issuerPubkeyHex).toBe("bb".repeat(32));
      expect(result.current.issuerKeyAutofilled).toBe(false);
    });
  });

  it("onFile transitions through hashing → ready when the bundle is also loaded", async () => {
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onBundleFile(makeBundleFile());
    });
    expect(result.current.stage).toBe("idle"); // no file yet
    await act(async () => {
      await result.current.onFile(makeFile());
    });
    expect(result.current.stage).toBe("ready");
    expect(result.current.fileHash).toBe("ff".repeat(32));
    expect(result.current.parsed?.format).toBe("text-line");
    expect(result.current.parsed?.segment_count).toBe(2);
    expect(result.current.parsed?.segments).toHaveLength(2);
  });

  it("rejects a legacy redaction_validity (V2) bundle with a clear message", async () => {
    const { result } = renderHook(() => useRedactionAudit());
    const f = new File(
      [JSON.stringify({ circuit: "redaction_validity", proof_json: {}, public_signals: [] })],
      "old.json",
      { type: "application/json" },
    );
    await act(async () => {
      await result.current.onBundleFile(f);
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/V2/);
  });

  it("rejects a bundle missing the format tag", async () => {
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onBundleFile(makeBundleFile({ format: undefined }));
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/format/);
  });

  it("rejects a bundle missing the signature", async () => {
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onBundleFile(makeBundleFile({ signature_hex: undefined }));
    });
    expect(result.current.stage).toBe("error");
    expect(result.current.error).toMatch(/signature_hex/);
  });

  it("audit short-circuits when no bundle is loaded", async () => {
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.audit();
    });
    expect(mockedVerify).not.toHaveBeenCalled();
    expect(result.current.stage).toBe("idle");
  });

  it("audit errors when no issuer pubkey is provided", async () => {
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
    expect(result.current.error).toMatch(/Ed25519 public key/);
    expect(mockedVerify).not.toHaveBeenCalled();
  });

  it("audit happy path: verified=true → stage=done", async () => {
    mockedVerify.mockReturnValue({ ok: true });
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onFile(makeFile());
    });
    await act(async () => {
      await result.current.onBundleFile(makeBundleFile());
    });
    act(() => result.current.setIssuerPubkey(ISSUER));
    await act(async () => {
      await result.current.audit();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    expect(result.current.verified).toBe(true);
    expect(result.current.verifyReason).toBeNull();
    expect(mockedVerify).toHaveBeenCalledWith(
      expect.objectContaining({ format: "text-line" }),
      expect.any(Uint8Array),
      ISSUER,
      "text-line",
    );
  });

  it("audit: verified=false → done with the reason surfaced", async () => {
    mockedVerify.mockReturnValue({ ok: false, reason: "fold != original_root" });
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onFile(makeFile());
    });
    await act(async () => {
      await result.current.onBundleFile(makeBundleFile());
    });
    act(() => result.current.setIssuerPubkey(ISSUER));
    await act(async () => {
      await result.current.audit();
    });
    await waitFor(() => expect(result.current.stage).toBe("done"));
    expect(result.current.verified).toBe(false);
    expect(result.current.verifyReason).toMatch(/fold != original_root/);
  });

  it("reset clears file + bundle + issuer key + verdict state", async () => {
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onFile(makeFile());
    });
    await act(async () => {
      await result.current.onBundleFile(makeBundleFile());
    });
    act(() => result.current.setIssuerPubkey(ISSUER));
    act(() => result.current.reset());
    expect(result.current.stage).toBe("idle");
    expect(result.current.parsed).toBeNull();
    expect(result.current.fileHash).toBeNull();
    expect(result.current.bundleName).toBeNull();
    expect(result.current.issuerPubkeyHex).toBe("");
  });

  it("a new file selection clears the previous audit verdict (stale-result protection)", async () => {
    mockedVerify.mockReturnValue({ ok: true });
    const { result } = renderHook(() => useRedactionAudit());
    await act(async () => {
      await result.current.onFile(makeFile("first.txt"));
    });
    await act(async () => {
      await result.current.onBundleFile(makeBundleFile());
    });
    act(() => result.current.setIssuerPubkey(ISSUER));
    await act(async () => {
      await result.current.audit();
    });
    expect(result.current.verified).toBe(true);

    await act(async () => {
      await result.current.onFile(makeFile("second.txt"));
    });
    expect(result.current.verified).toBeNull();
    expect(result.current.verifyReason).toBeNull();
  });
});
