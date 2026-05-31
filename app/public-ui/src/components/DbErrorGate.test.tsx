import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  getApiBase: vi.fn().mockResolvedValue("http://127.0.0.1:3737"),
}));
// BootProgress polls /health and renders a status overlay; stub it to a
// deterministic harness that calls onReady once on mount so DbErrorGate's
// "checking → ok / error" transition is what's under test.
vi.mock("./BootProgress", () => ({
  default: ({ onReady }: { onReady: () => void }) => {
    queueMicrotask(onReady);
    return <div data-testid="boot-progress-stub" />;
  },
}));

import DbErrorGate from "./DbErrorGate";

interface TauriInternals {
  __TAURI_INTERNALS__?: unknown;
}

function clearTauri() {
  delete (window as unknown as TauriInternals).__TAURI_INTERNALS__;
}

beforeEach(() => {
  clearTauri();
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("ok", { status: 200 })));
});

afterEach(() => {
  clearTauri();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("<DbErrorGate>", () => {
  it("renders the BootProgress overlay while checking", () => {
    render(
      <DbErrorGate>
        <div>app body</div>
      </DbErrorGate>,
    );
    expect(screen.getByTestId("boot-progress-stub")).toBeInTheDocument();
    expect(screen.queryByText("app body")).not.toBeInTheDocument();
  });

  it("renders the children when /health is ok and no Tauri error is reported", async () => {
    render(
      <DbErrorGate>
        <div>app body</div>
      </DbErrorGate>,
    );
    await waitFor(() => expect(screen.getByText("app body")).toBeInTheDocument());
  });

  it("renders the FATAL DB screen when /health returns JSON db:'failed'", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ db: "failed" }), { status: 503 }),
      ),
    );
    render(
      <DbErrorGate>
        <div>app body</div>
      </DbErrorGate>,
    );
    expect(
      await screen.findByText(/Database failed to start/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/FATAL.*DATABASE FAILURE/i)).toBeInTheDocument();
    expect(screen.queryByText("app body")).not.toBeInTheDocument();
  });

  it("falls back to 'Database unavailable (HTTP N)' when error body has no detail", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("not json", { status: 500 })),
    );
    render(
      <DbErrorGate>
        <div>app body</div>
      </DbErrorGate>,
    );
    expect(
      await screen.findByText(/Database unavailable.*HTTP 500/),
    ).toBeInTheDocument();
  });

  it("renders the RESTART APP button when in error state", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ db: "failed" }), { status: 503 }),
      ),
    );
    render(
      <DbErrorGate>
        <div>app body</div>
      </DbErrorGate>,
    );
    expect(
      await screen.findByRole("button", { name: /RESTART APP/i }),
    ).toBeInTheDocument();
  });

  it("renders the remediation hints (port 5433, writable, disk space, PG download)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ db: "failed" }), { status: 503 }),
      ),
    );
    render(
      <DbErrorGate>
        <div>app body</div>
      </DbErrorGate>,
    );
    await screen.findByText(/FATAL/i);
    expect(screen.getByText(/port 5433/i)).toBeInTheDocument();
    expect(screen.getByText(/writable/i)).toBeInTheDocument();
    expect(screen.getByText(/500 MB/i)).toBeInTheDocument();
  });
});
