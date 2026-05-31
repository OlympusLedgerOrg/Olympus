import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  getApiBase: vi.fn().mockResolvedValue("http://127.0.0.1:3737"),
}));

import { getApiBase } from "../lib/api";
import BootProgress from "./BootProgress";

const mockedGetApiBase = vi.mocked(getApiBase);

beforeEach(() => {
  mockedGetApiBase.mockResolvedValue("http://127.0.0.1:3737");
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<BootProgress>", () => {
  it("renders the INITIALISING stage on first paint", () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 503 })));
    render(<BootProgress onReady={vi.fn()} />);
    expect(screen.getByRole("status")).toBeInTheDocument();
    expect(screen.getByText(/INITIALISING/)).toBeInTheDocument();
  });

  it("calls onReady once /health returns ok", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("ok", { status: 200 })));
    const onReady = vi.fn();
    render(<BootProgress onReady={onReady} />);
    await waitFor(() => expect(onReady).toHaveBeenCalledTimes(1));
    // The health probe targets {base}/health
    expect(vi.mocked(fetch).mock.calls[0][0]).toBe("http://127.0.0.1:3737/health");
  });

  it("keeps polling (does not call onReady) while /health is not ok", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 503 })));
    const onReady = vi.fn();
    render(<BootProgress onReady={onReady} />);
    // Give the first probe a chance to resolve.
    await waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalled());
    expect(onReady).not.toHaveBeenCalled();
  });

  it("swallows a fetch rejection and stays on the boot screen", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("conn refused")));
    const onReady = vi.fn();
    render(<BootProgress onReady={onReady} />);
    await waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalled());
    expect(onReady).not.toHaveBeenCalled();
    expect(screen.getByRole("status")).toBeInTheDocument();
  });
});
