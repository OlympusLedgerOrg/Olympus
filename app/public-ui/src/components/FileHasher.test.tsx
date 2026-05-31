import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/blake3", () => ({
  hashFile: vi.fn(),
}));

import { hashFile } from "../lib/blake3";
import FileHasher from "./FileHasher";

const mockedHashFile = vi.mocked(hashFile);

function makeFile(name = "doc.pdf", size = 1024) {
  return new File([new Uint8Array(size)], name, { type: "application/pdf" });
}

beforeEach(() => {
  mockedHashFile.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<FileHasher>", () => {
  it("renders the empty-state prompt by default", () => {
    render(<FileHasher onHash={vi.fn()} onProgress={vi.fn()} />);
    expect(screen.getByText(/DROP_FILE_HERE/i)).toBeInTheDocument();
    expect(screen.getByText(/BLAKE3 WASM/)).toBeInTheDocument();
  });

  it("hashes a dropped file and emits the hex to onHash + 0% start to onProgress", async () => {
    const onHash = vi.fn();
    const onProgress = vi.fn();
    mockedHashFile.mockResolvedValue("ff".repeat(32));
    render(<FileHasher onHash={onHash} onProgress={onProgress} />);
    const file = makeFile("dropped.pdf");
    fireEvent.drop(screen.getByRole("button"), {
      dataTransfer: { files: [file] },
    });
    await waitFor(() => expect(onHash).toHaveBeenCalledWith("ff".repeat(32)));
    // onProgress(0) is fired before hashFile; intermediate calls come from
    // hashFile's progress callback (if any). The source does NOT call
    // onProgress(100) on completion — only the internal setProgress(100).
    expect(onProgress).toHaveBeenCalledWith(0);
  });

  it("forwards onFile when the trio is supplied", async () => {
    const onFile = vi.fn();
    mockedHashFile.mockResolvedValue("ab".repeat(32));
    render(<FileHasher onHash={vi.fn()} onProgress={vi.fn()} onFile={onFile} />);
    const file = makeFile();
    fireEvent.drop(screen.getByRole("button"), {
      dataTransfer: { files: [file] },
    });
    await waitFor(() => expect(onFile).toHaveBeenCalledWith(file));
  });

  it("shows HASHING: <filename> with a progress bar while in flight", async () => {
    // Promise that resolves only when we release it, so the hashing state
    // is observable.
    let release!: (h: string) => void;
    mockedHashFile.mockImplementation(
      () => new Promise<string>((r) => (release = r)),
    );
    render(<FileHasher onHash={vi.fn()} onProgress={vi.fn()} />);
    fireEvent.drop(screen.getByRole("button"), {
      dataTransfer: { files: [makeFile("doc.pdf")] },
    });
    expect(await screen.findByText(/HASHING:/)).toBeInTheDocument();
    expect(screen.getByText("doc.pdf")).toBeInTheDocument();
    release("ab".repeat(32));
  });

  it("renders an error message when hashFile rejects", async () => {
    mockedHashFile.mockRejectedValue(new Error("blake3 wasm blocked"));
    render(<FileHasher onHash={vi.fn()} onProgress={vi.fn()} />);
    fireEvent.drop(screen.getByRole("button"), {
      dataTransfer: { files: [makeFile()] },
    });
    expect(await screen.findByText(/blake3 wasm blocked/)).toBeInTheDocument();
  });

  it("file-input change fires the same hash pipeline as drop", async () => {
    const onHash = vi.fn();
    mockedHashFile.mockResolvedValue("cc".repeat(32));
    render(<FileHasher onHash={onHash} onProgress={vi.fn()} />);
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.change(input, { target: { files: [makeFile("via-input.pdf")] } });
    await waitFor(() => expect(onHash).toHaveBeenCalledWith("cc".repeat(32)));
  });

  it("after hashing completes, renders the file name + 'drop another' hint", async () => {
    mockedHashFile.mockResolvedValue("aa".repeat(32));
    render(<FileHasher onHash={vi.fn()} onProgress={vi.fn()} />);
    fireEvent.drop(screen.getByRole("button"), {
      dataTransfer: { files: [makeFile("done.pdf", 2 * 1024 * 1024)] },
    });
    await waitFor(
      () => expect(screen.getByText("done.pdf")).toBeInTheDocument(),
      { timeout: 3000 },
    );
    // "drop another" appears inline with the file-size text (line-broken
    // via <br/> in the source) — use a function matcher so line breaks
    // don't fail substring matching.
    expect(
      screen.getByText((text) => /drop another/i.test(text)),
    ).toBeInTheDocument();
    // 2 MB formatted as "2.0 MB"
    expect(screen.getByText((text) => /2\.0 MB/.test(text))).toBeInTheDocument();
  });

  it("Enter and Space on the drop region trigger the hidden file input click", () => {
    render(<FileHasher onHash={vi.fn()} onProgress={vi.fn()} />);
    const region = screen.getByRole("button");
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    const clickSpy = vi.spyOn(input, "click");
    fireEvent.keyDown(region, { key: "Enter" });
    // The keyDown handler + browser default Enter-on-button-role-element
    // both fire .click(), so each key press registers twice — verify the
    // pipeline triggers, not the exact count.
    fireEvent.keyDown(region, { key: " " });
    expect(clickSpy).toHaveBeenCalled();
    expect(clickSpy.mock.calls.length).toBeGreaterThanOrEqual(2);
  });
});
