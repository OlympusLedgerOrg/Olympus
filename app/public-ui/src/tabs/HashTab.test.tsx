import { fireEvent, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { describe, expect, it, vi } from "vitest";
import HashTab from "./HashTab";
import { renderWithSkin } from "../__tests__/render";
import { SAMPLE_HASH } from "../lib/constants";

// FileHasher pulls in BLAKE3 WASM (`../lib/blake3`) which isn't worth
// loading in unit tests of HashTab itself — the FileHasher contract
// (onHash, onProgress, onFile) is what HashTab depends on, not the
// hashing code path.
vi.mock("../components/FileHasher", () => ({
  default: ({ onHash }: { onHash: (h: string) => void }) => (
    <button type="button" data-testid="file-hasher-mock" onClick={() => onHash("ff".repeat(32))}>
      file-hasher
    </button>
  ),
}));

// Pull the prop type off the component itself so each field has the widest
// type the source accepts (e.g. `hashError: string | null`, `tone: "ok" |
// "warn" | "err" | "neutral"`) — otherwise TS infers each `baseProps` field
// at its concrete literal type and overrides like `tone: "warn"` or
// `hashError: "..."` fail to compile.
type HashTabProps = ComponentProps<typeof HashTab>;

const baseProps: HashTabProps = {
  hashInput: "",
  setHashInput: vi.fn(),
  hashError: null,
  hashStatus: { label: "READY", tone: "ok" },
  isPending: false,
  onSubmit: vi.fn(),
  onPaste: vi.fn().mockResolvedValue(undefined),
  onClear: vi.fn(),
  apiKey: "",
  setApiKey: vi.fn(),
};

function setup(overrides: Partial<HashTabProps> = {}) {
  const props: HashTabProps = { ...baseProps, ...overrides };
  return { props, ...renderWithSkin(<HashTab {...props} />) };
}

describe("<HashTab>", () => {
  it("renders the API-key + hash input fields by default", () => {
    setup();
    expect(screen.getByLabelText(/API key/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/BLAKE3 content hash/i)).toBeInTheDocument();
  });

  it("shows the wasmError banner when present", () => {
    setup({ wasmError: "WASM blocked by CSP" });
    expect(screen.getByText(/WASM blocked by CSP/)).toBeInTheDocument();
  });

  it("calls setApiKey when the API-key field changes", async () => {
    const { props } = setup();
    await userEvent.type(screen.getByLabelText(/API key/i), "x");
    expect(props.setApiKey).toHaveBeenCalledWith("x");
  });

  it("calls setHashInput on hash-field input", () => {
    const { props } = setup();
    fireEvent.change(screen.getByLabelText(/BLAKE3 content hash/i), {
      target: { value: "deadbeef" },
    });
    expect(props.setHashInput).toHaveBeenCalledWith("deadbeef");
  });

  it("calls onSubmit when VERIFY_HASH is clicked", async () => {
    const { props } = setup({ hashInput: SAMPLE_HASH });
    await userEvent.click(screen.getByRole("button", { name: /VERIFY_HASH/i }));
    expect(props.onSubmit).toHaveBeenCalledWith(SAMPLE_HASH);
  });

  it("calls onSubmit when Enter is pressed in the hash field", () => {
    const { props } = setup({ hashInput: SAMPLE_HASH });
    fireEvent.keyDown(screen.getByLabelText(/BLAKE3 content hash/i), { key: "Enter" });
    expect(props.onSubmit).toHaveBeenCalledWith(SAMPLE_HASH);
  });

  it("disables VERIFY when hashStatus is not ok", () => {
    setup({ hashStatus: { label: "TOO SHORT", tone: "warn" } });
    expect(screen.getByRole("button", { name: /VERIFY_HASH/i })).toBeDisabled();
  });

  it("shows EXECUTING... while pending and disables VERIFY", () => {
    setup({ hashInput: SAMPLE_HASH, isPending: true });
    const verify = screen.getByRole("button", { name: /EXECUTING/i });
    expect(verify).toBeDisabled();
  });

  it("PASTE calls onPaste", async () => {
    const { props } = setup();
    await userEvent.click(screen.getByRole("button", { name: /PASTE/i }));
    expect(props.onPaste).toHaveBeenCalled();
  });

  it("SAMPLE pre-fills the hash input with SAMPLE_HASH", async () => {
    const { props } = setup();
    await userEvent.click(screen.getByRole("button", { name: /SAMPLE/i }));
    expect(props.setHashInput).toHaveBeenCalledWith(SAMPLE_HASH);
  });

  it("CLEAR calls onClear", async () => {
    const { props } = setup();
    await userEvent.click(screen.getByRole("button", { name: /CLEAR/i }));
    expect(props.onClear).toHaveBeenCalled();
  });

  it("renders the hashError text when present", () => {
    setup({ hashError: "Hash must be 64 hex chars" });
    expect(screen.getByText(/Hash must be 64 hex chars/)).toBeInTheDocument();
  });

  it("hides FileHasher when the onFile/onFileHash/onFileProgress trio isn't passed", () => {
    setup();
    expect(screen.queryByTestId("file-hasher-mock")).not.toBeInTheDocument();
  });

  it("renders FileHasher when the trio is supplied and forwards the hash via setHashInput + onSubmit", async () => {
    const onFile = vi.fn();
    const onFileHash = vi.fn();
    const onFileProgress = vi.fn();
    const { props } = setup({ onFile, onFileHash, onFileProgress, fileProgress: 0 });
    await userEvent.click(screen.getByTestId("file-hasher-mock"));
    expect(onFileHash).toHaveBeenCalledWith("ff".repeat(32));
    expect(props.setHashInput).toHaveBeenCalledWith("ff".repeat(32));
    expect(props.onSubmit).toHaveBeenCalledWith("ff".repeat(32), "file");
  });

  it("shows the HASHING_FILE progress label only when 0 < fileProgress < 100", () => {
    const onFile = vi.fn();
    const onFileHash = vi.fn();
    const onFileProgress = vi.fn();

    // 0% — hidden
    const { unmount } = setup({ onFile, onFileHash, onFileProgress, fileProgress: 0 });
    expect(screen.queryByText(/HASHING_FILE/)).not.toBeInTheDocument();
    unmount();

    // 50% — shown
    setup({ onFile, onFileHash, onFileProgress, fileProgress: 50 });
    expect(screen.getByText(/HASHING_FILE\.\.\. 50%/)).toBeInTheDocument();
  });
});
