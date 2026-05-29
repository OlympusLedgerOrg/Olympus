import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { renderWithSkin } from "../__tests__/render";

// `hashFile` pulls in the BLAKE3 WASM module, which isn't worth loading in a
// unit test — stub it so we control the digest the page renders.
vi.mock("../lib/blake3", () => ({
  hashFile: vi.fn(),
}));
// `apiFetch` is the only network surface; stub it so COMMIT never hits a server.
vi.mock("../lib/api", () => ({
  apiFetch: vi.fn(),
}));

import { hashFile } from "../lib/blake3";
import { apiFetch } from "../lib/api";
// Spy on (rather than factory-mock) the real storage module so the component's
// render/validation path keeps working. The API key lives in a module-level
// in-memory variable inside storage.ts and is deliberately NEVER written to
// localStorage (documented security model); "the persisted store" therefore
// means setStoredApiKey / getStoredApiKey / clearStoredApiKey.
import * as storage from "../lib/storage";
import IngestPage from "./IngestPage";

const mockHashFile = vi.mocked(hashFile);
const mockApiFetch = vi.mocked(apiFetch);

// A full 64-hex key so `apiKeyProblem()` (/^[0-9a-f]{64}$/i) accepts it.
const VALID_KEY = "a".repeat(64);
// A distinctive full-length (64-hex) digest. Asserting against the COMPLETE
// value — rather than a permissive `/ff{16,}/`-style substring — means the
// test only passes when the whole digest is rendered.
const MOCKED_DIGEST = "deadbeef".repeat(8);

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<IngestPage>", () => {
  it("renders the COMMIT TO LEDGER heading", () => {
    renderWithSkin(<IngestPage />);
    expect(screen.getByRole("heading", { name: /COMMIT TO LEDGER/i })).toBeInTheDocument();
  });

  it("hashes a picked file and renders the full 64-hex BLAKE3 digest", async () => {
    mockHashFile.mockResolvedValue(MOCKED_DIGEST);
    renderWithSkin(<IngestPage />);

    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    const file = new File(["hello"], "hello.txt", { type: "text/plain" });
    // The file input is `display:none` (clicked via a styled drop zone), so
    // drive it with fireEvent.change rather than user.upload.
    fireEvent.change(fileInput, { target: { files: [file] } });

    await waitFor(() => expect(mockHashFile).toHaveBeenCalledTimes(1));

    // Assert the COMPLETE 64-character hex digest is rendered — the matched
    // element's full text must equal MOCKED_DIGEST, so a partial/truncated
    // render would fail this test.
    const matches = await screen.findAllByText(
      (_, el) => el?.textContent === MOCKED_DIGEST,
    );
    expect(matches.length).toBeGreaterThan(0);
  });

  it("CLEAR KEY wipes the API key field and the persisted store", async () => {
    // Persist the key first: back the storage accessors with a stateful spy so
    // the page hydrates its field from the store at mount (useState initializer
    // reads getStoredApiKey()), and so clearing actually empties the store.
    let stored = VALID_KEY;
    vi.spyOn(storage, "getStoredApiKey").mockImplementation(() => stored);
    const clearSpy = vi
      .spyOn(storage, "clearStoredApiKey")
      .mockImplementation(() => {
        stored = "";
      });

    renderWithSkin(<IngestPage />);

    const keyField = document.querySelector('input[type="password"]') as HTMLInputElement;
    // The field is pre-filled from the persisted store, and the store holds it.
    expect(keyField.value).toBe(VALID_KEY);
    expect(storage.getStoredApiKey()).toBe(VALID_KEY);

    fireEvent.click(screen.getByRole("button", { name: /CLEAR KEY/i }));

    // Both the UI field and the persisted store must be cleared: the input is
    // emptied, the page invokes the store's clear API, and the store no longer
    // holds the key.
    await waitFor(() => expect(keyField.value).toBe(""));
    expect(clearSpy).toHaveBeenCalled();
    expect(storage.getStoredApiKey()).toBe("");
  });

  it("gates COMMIT behind a valid API key", async () => {
    mockHashFile.mockResolvedValue(MOCKED_DIGEST);
    renderWithSkin(<IngestPage />);

    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.change(fileInput, {
      target: { files: [new File(["hi"], "hi.txt", { type: "text/plain" })] },
    });

    // With no key entered the commit button is disabled and labelled as a prompt.
    const commitBtn = (await screen.findByRole("button", {
      name: /ENTER API KEY ABOVE TO COMMIT/i,
    })) as HTMLButtonElement;
    expect(commitBtn).toBeDisabled();
    expect(mockApiFetch).not.toHaveBeenCalled();
  });
});
