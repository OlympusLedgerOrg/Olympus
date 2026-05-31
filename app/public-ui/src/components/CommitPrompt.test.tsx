import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { describe, expect, it, vi } from "vitest";
import CommitPrompt from "./CommitPrompt";

type CommitPromptProps = ComponentProps<typeof CommitPrompt>;

const baseProps: CommitPromptProps = {
  apiKey: "",
  setApiKey: vi.fn(),
  commitStage: "idle",
  commitError: null,
  onCommit: vi.fn().mockResolvedValue(undefined),
  onReset: vi.fn(),
  originalHash: "",
  setOriginalHash: vi.fn(),
};

function setup(overrides: Partial<CommitPromptProps> = {}) {
  const props: CommitPromptProps = { ...baseProps, ...overrides };
  return { props, ...render(<CommitPrompt {...props} />) };
}

describe("<CommitPrompt>", () => {
  it("renders the COMMIT THIS FILE banner + original-hash field by default", () => {
    setup();
    expect(screen.getByText(/COMMIT THIS FILE TO THE LEDGER/i)).toBeInTheDocument();
    expect(
      screen.getByPlaceholderText(/paste BLAKE3 hash of original document/i),
    ).toBeInTheDocument();
  });

  it("COMMIT TO LEDGER button is disabled until an API key is present", () => {
    setup();
    const btn = screen.getByRole("button", { name: /COMMIT TO LEDGER/i });
    expect(btn).toBeDisabled();
  });

  it("becomes enabled once apiKey is non-empty", () => {
    setup({ apiKey: "oly_key" });
    expect(screen.getByRole("button", { name: /COMMIT TO LEDGER/i })).toBeEnabled();
  });

  it("shows COMMITTING... when stage is 'committing' and disables the button", () => {
    setup({ apiKey: "k", commitStage: "committing" });
    const btn = screen.getByRole("button", { name: /COMMITTING/i });
    expect(btn).toBeDisabled();
  });

  it("REDACTION_MODE banner appears when originalHash is set", () => {
    setup({ originalHash: "abc" });
    expect(screen.getByText(/REDACTION_MODE/)).toBeInTheDocument();
  });

  it("setOriginalHash is called when the field is edited", () => {
    const { props } = setup();
    fireEvent.change(
      screen.getByPlaceholderText(/paste BLAKE3 hash of original document/i),
      { target: { value: "deadbeef" } },
    );
    expect(props.setOriginalHash).toHaveBeenCalledWith("deadbeef");
  });

  it("clicking COMMIT TO LEDGER fires onCommit", async () => {
    const { props } = setup({ apiKey: "k" });
    await userEvent.click(screen.getByRole("button", { name: /COMMIT TO LEDGER/i }));
    expect(props.onCommit).toHaveBeenCalled();
  });

  it("renders a plain error message for non-auth errors", () => {
    setup({ apiKey: "k", commitError: "server timeout" });
    expect(screen.getByText("server timeout")).toBeInTheDocument();
    // No inline API-key field for non-auth errors
    expect(screen.queryByPlaceholderText(/paste a valid API key/i)).not.toBeInTheDocument();
  });

  it("auth errors surface an inline API-key field + RETRY / CLEAR buttons", () => {
    setup({ apiKey: "old-key", commitError: "Authentication failed: invalid api key" });
    expect(screen.getByPlaceholderText(/paste a valid API key/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /RETRY/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /CLEAR/i })).toBeInTheDocument();
  });

  it("auth-error variants: invalid api key, auth_invalid, auth_expired all trigger the inline form", () => {
    for (const msg of ["invalid api key", "auth_invalid", "auth_expired"]) {
      const { unmount } = setup({ apiKey: "k", commitError: msg });
      expect(screen.getByPlaceholderText(/paste a valid API key/i)).toBeInTheDocument();
      unmount();
    }
  });

  it("auth-error CLEAR button wipes apiKey and calls onReset", async () => {
    const { props } = setup({ apiKey: "old", commitError: "authentication failed" });
    await userEvent.click(screen.getByRole("button", { name: /CLEAR/i }));
    expect(props.setApiKey).toHaveBeenCalledWith("");
    expect(props.onReset).toHaveBeenCalled();
  });

  it("auth-error RETRY button fires onCommit when the new key is valid", async () => {
    const { props } = setup({ apiKey: "fresh-key", commitError: "authentication failed" });
    await userEvent.click(screen.getByRole("button", { name: /RETRY/i }));
    expect(props.onCommit).toHaveBeenCalled();
  });
});
