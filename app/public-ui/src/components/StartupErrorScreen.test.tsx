import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import StartupErrorScreen from "./StartupErrorScreen";
import { tauriInvoke } from "../lib/api";

// StartupErrorScreen calls tauriInvoke("get_startup_error"); mock that supported
// Tauri 2 path (api.ts gates on __TAURI_INTERNALS__ + dynamic import). The old
// tests shimmed window.__TAURI__, a global that is never injected at runtime
// (withGlobalTauri unset), so they masked a real surfacing defect.
vi.mock("../lib/api", () => ({
  tauriInvoke: vi.fn(),
}));

const mockedInvoke = vi.mocked(tauriInvoke);

beforeEach(() => {
  // Default: not under Tauri (tauriInvoke resolves null).
  mockedInvoke.mockResolvedValue(null);
});

afterEach(() => {
  vi.restoreAllMocks();
  mockedInvoke.mockReset();
});

describe("<StartupErrorScreen>", () => {
  it("renders children unchanged when the Tauri runtime is absent", async () => {
    mockedInvoke.mockResolvedValue(null);
    render(
      <StartupErrorScreen>
        <div>app content</div>
      </StartupErrorScreen>,
    );
    await new Promise((r) => setTimeout(r, 0));
    expect(screen.getByText("app content")).toBeInTheDocument();
    expect(screen.queryByText(/STARTUP HALTED/)).not.toBeInTheDocument();
  });

  it("renders children when get_startup_error returns null", async () => {
    mockedInvoke.mockResolvedValue(null);
    render(
      <StartupErrorScreen>
        <div>app content</div>
      </StartupErrorScreen>,
    );
    await new Promise((r) => setTimeout(r, 0));
    expect(screen.getByText("app content")).toBeInTheDocument();
  });

  it("renders the FATAL overlay with message + code when an error is present", async () => {
    mockedInvoke.mockResolvedValue({
      code: "ZK_PLACEHOLDER",
      message: "A ZK artifact is still a placeholder stub.",
    });
    render(
      <StartupErrorScreen>
        <div>app content</div>
      </StartupErrorScreen>,
    );
    expect(await screen.findByText(/STARTUP HALTED/)).toBeInTheDocument();
    expect(screen.getByText(/ZK artifact is still a placeholder/)).toBeInTheDocument();
    expect(screen.getByText(/code: ZK_PLACEHOLDER/)).toBeInTheDocument();
    // The overlay replaces the children
    expect(screen.queryByText("app content")).not.toBeInTheDocument();
  });

  it("renders a docs link when doc_url is present", async () => {
    mockedInvoke.mockResolvedValue({
      code: "X",
      message: "boom",
      doc_url: "https://docs.example/startup",
    });
    render(
      <StartupErrorScreen>
        <div>child</div>
      </StartupErrorScreen>,
    );
    const link = await screen.findByRole("link", { name: /read docs/i });
    expect(link).toHaveAttribute("href", "https://docs.example/startup");
  });

  it("renders children if the invoke promise rejects", async () => {
    mockedInvoke.mockRejectedValue(new Error("ipc down"));
    render(
      <StartupErrorScreen>
        <div>app content</div>
      </StartupErrorScreen>,
    );
    await waitFor(() => expect(screen.getByText("app content")).toBeInTheDocument());
  });
});
