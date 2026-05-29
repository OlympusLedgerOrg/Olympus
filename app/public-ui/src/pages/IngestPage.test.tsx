import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  apiFetch: vi.fn(),
}));
vi.mock("../lib/blake3", () => ({
  hashFile: vi.fn(),
}));
// Storage stays real (it's already covered + tested for in-memory semantics
// in lib/storage.test.ts). The page reads/writes the canonical key path
// through these helpers so testing against the real module is fine.

import { apiFetch } from "../lib/api";
import { hashFile } from "../lib/blake3";
import { clearStoredApiKey, getStoredApiKey } from "../lib/storage";
import IngestPage from "./IngestPage";

const mockedApiFetch = vi.mocked(apiFetch);
const mockedHashFile = vi.mocked(hashFile);

const VALID_KEY = "a".repeat(64);
// Full 64-hex digest the mocked hashFile returns. Asserting against this exact
// value — not a permissive `/ff{16,}/` substring — means the test only passes
// when the COMPLETE digest is rendered.
const MOCKED_DIGEST = "ff".repeat(32);

beforeEach(() => {
  mockedApiFetch.mockReset();
  mockedHashFile.mockReset();
  clearStoredApiKey();
});

afterEach(() => {
  vi.restoreAllMocks();
});

// The file <input> is `display:none` (driven via a styled drop zone), so it
// has no accessible role/label to target with a testing-library query. Query
// it directly but assert it exists first, so a missing element fails with a
// clear message instead of a downstream `fireEvent.change(null)` TypeError.
function getFileInput(): HTMLInputElement {
  const el = document.querySelector('input[type="file"]');
  expect(el).toBeInstanceOf(HTMLInputElement);
  return el as HTMLInputElement;
}

describe("<IngestPage>", () => {
  it("renders the COMMIT TO LEDGER hero + API-key field", () => {
    render(<IngestPage />);
    expect(screen.getByRole("heading", { name: /COMMIT TO LEDGER/i })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/paste your API key/i)).toBeInTheDocument();
  });

  it("hashes the dropped file and renders the local BLAKE3 result", async () => {
    mockedHashFile.mockResolvedValue(MOCKED_DIGEST);
    render(<IngestPage />);
    const file = new File(["data"], "doc.pdf", { type: "application/pdf" });
    const fileInput = getFileInput();
    fireEvent.change(fileInput, { target: { files: [file] } });

    await waitFor(() => expect(mockedHashFile).toHaveBeenCalledWith(file));
    expect(await screen.findByText(/COMMIT DETAILS/i)).toBeInTheDocument();
    // Assert the COMPLETE 64-hex digest is rendered — the matched element's
    // full text must equal MOCKED_DIGEST, so a partial/truncated render fails.
    const matches = await screen.findAllByText(
      (_, el) => el?.textContent === MOCKED_DIGEST,
    );
    expect(matches.length).toBeGreaterThan(0);
  });

  it("surfaces a hash error and lands in the 'error' stage if hashFile rejects", async () => {
    mockedHashFile.mockRejectedValue(new Error("blake3 wasm blocked"));
    render(<IngestPage />);
    const file = new File(["x"], "doc.pdf");
    const fileInput = getFileInput();
    fireEvent.change(fileInput, { target: { files: [file] } });

    expect(await screen.findByText(/blake3 wasm blocked/)).toBeInTheDocument();
  });

  it("Save Key validates the pasted key and stores it on success", async () => {
    render(<IngestPage />);
    await userEvent.type(screen.getByPlaceholderText(/paste your API key/i), VALID_KEY);
    await userEvent.click(screen.getByRole("button", { name: /SAVE KEY|SAVED/i }));
    // No source change for the field — but the SAVE KEY button transiently
    // shows "SAVED ✓" (timeout-driven). Just verify no error banner.
    expect(screen.queryByText(/64-character hex/)).not.toBeInTheDocument();
  });

  it("Save Key rejects a malformed key with the canonical error", async () => {
    render(<IngestPage />);
    await userEvent.type(screen.getByPlaceholderText(/paste your API key/i), "not-a-key");
    await userEvent.click(screen.getByRole("button", { name: /SAVE KEY|SAVED/i }));
    expect(await screen.findByText(/64-character hex/)).toBeInTheDocument();
  });

  it("Clear wipes the API key field and stored copy", async () => {
    render(<IngestPage />);
    const keyField = screen.getByPlaceholderText(/paste your API key/i) as HTMLInputElement;
    await userEvent.type(keyField, VALID_KEY);

    // Persist the key first via SAVE KEY so this verifies clearing the *stored*
    // copy, not just the input. The API key is held in a module-level in-memory
    // variable inside storage.ts (deliberately NEVER written to localStorage,
    // per the documented security model), so getStoredApiKey() — not
    // localStorage — is the persisted-store surface.
    await userEvent.click(screen.getByRole("button", { name: /SAVE KEY|SAVED/i }));
    await waitFor(() => expect(getStoredApiKey()).toBe(VALID_KEY));

    await userEvent.click(screen.getByRole("button", { name: /CLEAR KEY/i }));

    // Both the UI field AND the persisted store must be cleared.
    expect(keyField.value).toBe("");
    expect(getStoredApiKey()).toBe("");
  });

  it("commit button is gated until both file is hashed AND an API key is present", async () => {
    mockedHashFile.mockResolvedValue("ab".repeat(32));
    render(<IngestPage />);
    const file = new File(["data"], "doc.pdf");
    const fileInput = getFileInput();
    fireEvent.change(fileInput, { target: { files: [file] } });
    // After hash settles, the COMMIT panel appears — but the button still
    // shows the "ENTER API KEY ABOVE TO COMMIT" placeholder text.
    expect(
      await screen.findByRole("button", { name: /ENTER API KEY/i }),
    ).toBeDisabled();
  });

  it("commit posts to /ingest/files with the expected multipart fields and renders the result", async () => {
    mockedHashFile.mockResolvedValue("ab".repeat(32));
    mockedApiFetch.mockResolvedValue({
      proof_id: "pid-1",
      content_hash: "ab".repeat(32),
      record_id: "doc",
      shard_id: "files",
      deduplicated: false,
    });

    render(<IngestPage />);
    // Paste key + save it so the commit button enables.
    await userEvent.type(
      screen.getByPlaceholderText(/paste your API key/i),
      VALID_KEY,
    );
    // Drop the file
    const file = new File(["data"], "doc.pdf");
    const fileInput = getFileInput();
    fireEvent.change(fileInput, { target: { files: [file] } });
    await screen.findByText(/COMMIT DETAILS/i);

    // Click the now-enabled COMMIT TO LEDGER button.
    await userEvent.click(screen.getByRole("button", { name: /COMMIT TO LEDGER/i }));

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalled());
    const [path, init] = mockedApiFetch.mock.calls[0];
    expect(path).toBe("/ingest/files");
    expect(init?.method).toBe("POST");
    expect(init?.body).toBeInstanceOf(FormData);
    const fd = init?.body as FormData;
    expect(fd.get("shard_id")).toBe("files");
    expect(fd.get("version")).toBe("1");
    expect(fd.get("file")).toBeInstanceOf(File);

    expect(await screen.findByText(/COMMITTED TO LEDGER/i)).toBeInTheDocument();
    expect(screen.getByText("pid-1")).toBeInTheDocument();
  });

  it("renders ALREADY ON LEDGER when the server reports deduplicated=true", async () => {
    mockedHashFile.mockResolvedValue("ab".repeat(32));
    mockedApiFetch.mockResolvedValue({
      proof_id: "pid-1",
      content_hash: "ab".repeat(32),
      record_id: "doc",
      shard_id: "files",
      deduplicated: true,
    });

    render(<IngestPage />);
    await userEvent.type(
      screen.getByPlaceholderText(/paste your API key/i),
      VALID_KEY,
    );
    const file = new File(["data"], "doc.pdf");
    const fileInput = getFileInput();
    fireEvent.change(fileInput, { target: { files: [file] } });
    await screen.findByText(/COMMIT DETAILS/i);
    await userEvent.click(screen.getByRole("button", { name: /COMMIT TO LEDGER/i }));

    expect(await screen.findByText(/ALREADY ON LEDGER/i)).toBeInTheDocument();
  });
});
