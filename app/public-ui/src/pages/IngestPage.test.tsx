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
// through these helpers so testing against the real module is fine — and the
// CLEAR-KEY test asserts against getStoredApiKey() to prove the persisted copy
// is wiped. (The API key lives in a module-level in-memory variable inside
// storage.ts and is deliberately NEVER written to localStorage, per the
// documented security model — so getStoredApiKey() is the persisted-store
// surface, not localStorage.)

import { apiFetch } from "../lib/api";
import { hashFile } from "../lib/blake3";
import { clearStoredApiKey, getStoredApiKey } from "../lib/storage";
import IngestPage from "./IngestPage";

const mockedApiFetch = vi.mocked(apiFetch);
const mockedHashFile = vi.mocked(hashFile);

const VALID_KEY = "a".repeat(64);
// Full 64-hex digest the mocked hashFile returns. Asserting against this exact
// value — rather than a permissive `/ff{16,}/` substring — means the test only
// passes when the COMPLETE digest is rendered.
const MOCKED_DIGEST = "ff".repeat(32);

beforeEach(() => {
  mockedApiFetch.mockReset();
  mockedHashFile.mockReset();
  clearStoredApiKey();
});

afterEach(() => {
  vi.restoreAllMocks();
  clearStoredApiKey();
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
    const matches = await screen.findAllByText((_, el) => el?.textContent === MOCKED_DIGEST);
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
    // copy, not just the input. getStoredApiKey() reads the same in-memory
    // store the page writes to via setStoredApiKey.
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
    expect(await screen.findByRole("button", { name: /ENTER API KEY/i })).toBeDisabled();
  });

  it("commit posts to /ingest/files with the expected multipart fields and renders the result", async () => {
    mockedHashFile.mockResolvedValue("ab".repeat(32));
    mockedApiFetch.mockResolvedValue({
      proof_id: "pid-1",
      content_hash: "ab".repeat(32),
      record_id: "doc",
      shard_id: "files",
      deduplicated: false,
      redaction_format: "pdf-object",
    });

    render(<IngestPage />);
    // Paste key + save it so the commit button enables.
    await userEvent.type(screen.getByPlaceholderText(/paste your API key/i), VALID_KEY);
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
    // Object is the conservative default — word must stay strictly opt-in.
    expect(fd.get("granularity")).toBe("object");
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
      redaction_format: null,
    });

    render(<IngestPage />);
    await userEvent.type(screen.getByPlaceholderText(/paste your API key/i), VALID_KEY);
    const file = new File(["data"], "doc.pdf");
    const fileInput = getFileInput();
    fireEvent.change(fileInput, { target: { files: [file] } });
    await screen.findByText(/COMMIT DETAILS/i);
    await userEvent.click(screen.getByRole("button", { name: /COMMIT TO LEDGER/i }));

    expect(await screen.findByText(/ALREADY ON LEDGER/i)).toBeInTheDocument();
  });

  /** Drive the page to a committed result with the given granularity choice and
   *  server response. Word granularity is opt-in, so the select must be changed
   *  before committing. */
  async function commitWith(granularity: string, response: Record<string, unknown>) {
    mockedHashFile.mockResolvedValue("ab".repeat(32));
    mockedApiFetch.mockResolvedValue(response);
    render(<IngestPage />);
    await userEvent.type(screen.getByPlaceholderText(/paste your API key/i), VALID_KEY);
    fireEvent.change(getFileInput(), { target: { files: [new File(["data"], "doc.pdf")] } });
    await screen.findByText(/COMMIT DETAILS/i);
    if (granularity !== "object") {
      await userEvent.selectOptions(screen.getByLabelText(/redaction granularity/i), granularity);
    }
    await userEvent.click(screen.getByRole("button", { name: /COMMIT TO LEDGER/i }));
    await waitFor(() => {
      expect(mockedApiFetch).toHaveBeenCalled();
    });
  }

  const committed = (redaction_format: string | null) => ({
    proof_id: "pid-1",
    content_hash: "ab".repeat(32),
    record_id: "doc",
    shard_id: "files",
    deduplicated: false,
    redaction_format,
  });

  it("sends the chosen granularity (ADR-0029 B1)", async () => {
    // Without this the word-selection UI is unreachable for anything ingested
    // through the desktop app — every document would commit at object
    // granularity regardless of what the operator picked.
    await commitWith("word", committed("pdf-textrun"));
    const fd = mockedApiFetch.mock.calls[0][1]?.body as FormData;
    expect(fd.get("granularity")).toBe("word");
  });

  it("warns when word granularity was requested but not applied", async () => {
    // The server declines word for a scanned PDF, a document past the segment
    // cap, or an unparsable structure, and commits at object granularity. That
    // is correct, but the operator asked for something they did not get.
    await commitWith("word", committed("pdf-xref-stream"));
    expect(await screen.findByText(/could not be applied to this document/i)).toBeInTheDocument();
    expect(screen.getByText("pdf-xref-stream")).toBeInTheDocument();
  });

  it("names the committed format without claiming object redaction", async () => {
    // `granularity` steers only the PDF branch of segmentation, so a text
    // upload commits as `text-line` regardless — and line-block redaction is
    // not whole-object redaction. The warning must name the format rather than
    // describe what it offers, or it misstates what the operator will get.
    await commitWith("word", committed("text-line"));
    expect(await screen.findByText(/could not be applied to this document/i)).toBeInTheDocument();
    expect(screen.getByText("text-line")).toBeInTheDocument();
    expect(screen.queryByText(/whole objects/i)).not.toBeInTheDocument();
  });

  it("stays quiet when word granularity was honoured", async () => {
    await commitWith("word", committed("pdf-textrun"));
    await screen.findByText(/COMMITTED TO LEDGER/i);
    expect(screen.queryByText(/could not be applied/i)).not.toBeInTheDocument();
  });

  it("says a word request had no effect on content already committed", async () => {
    // `redaction_format` is null on a deduplicated upload — nothing was
    // segmented, so there is no demotion to report and claiming one would be
    // wrong. But silence is not the answer either: the operator asked for word
    // and got the first ingest's granularity, and the insert-only ledger means
    // no re-upload will ever change that. Say so here instead of letting them
    // find out in the redaction tab.
    await commitWith("word", { ...committed(null), deduplicated: true });
    await screen.findByText(/ALREADY ON LEDGER/i);
    expect(screen.getByText(/the word request had no effect/i)).toBeInTheDocument();
    expect(screen.getByText(/insert-only/i)).toBeInTheDocument();
    // Specifically NOT the demotion wording: nothing was demoted, and this
    // response does not carry the committed format to name.
    expect(screen.queryByText(/could not be applied/i)).not.toBeInTheDocument();
  });

  it("stays quiet on a deduplicated upload the operator did not ask to re-cut", async () => {
    // Object is the default, and a record already committed at object *or*
    // word granularity satisfies it — there is nothing the operator asked for
    // and did not get, so a notice would just be noise on the common path.
    await commitWith("object", { ...committed(null), deduplicated: true });
    await screen.findByText(/ALREADY ON LEDGER/i);
    expect(screen.queryByText(/had no effect/i)).not.toBeInTheDocument();
  });

  it("warns when a fresh commit could not be segmented at all", async () => {
    // `redaction_format: null` with `deduplicated: false` means no segmenter
    // took the document, so it committed the chunk-root fallback: no words AND
    // no objects. "COMMITTED TO LEDGER ✓" alone implies a redaction affordance
    // that does not exist for this record.
    await commitWith("object", committed(null));
    await screen.findByText(/COMMITTED TO LEDGER/i);
    expect(screen.getByText(/could not be segmented for redaction/i)).toBeInTheDocument();
  });

  it("warns about an unsegmentable commit whichever granularity was asked for", async () => {
    // The record has no redactable segments either way, so this one is not
    // conditioned on the request — unlike the two notices above it.
    await commitWith("word", committed(null));
    await screen.findByText(/COMMITTED TO LEDGER/i);
    expect(screen.getByText(/could not be segmented for redaction/i)).toBeInTheDocument();
  });

  it("never warns when the operator did not ask for word granularity", async () => {
    await commitWith("object", committed("pdf-object"));
    await screen.findByText(/COMMITTED TO LEDGER/i);
    expect(screen.queryByText(/could not be applied/i)).not.toBeInTheDocument();
  });
});
