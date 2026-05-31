import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../lib/api";
import ScopeBanner from "./ScopeBanner";

let client: QueryClient;

function renderBanner() {
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <ScopeBanner />
    </QueryClientProvider>,
  );
}

// Push an error through the mutation cache the same way a failed mutation
// would — this is the channel ScopeBanner subscribes to.
async function emitMutationError(err: unknown) {
  const mutation = client.getMutationCache().build(client, {
    mutationFn: () => Promise.reject(err),
  });
  await mutation.execute(undefined).catch(() => {});
}

beforeEach(() => {
  vi.useRealTimers();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<ScopeBanner>", () => {
  it("renders nothing initially", () => {
    const { container } = renderBanner();
    expect(container).toBeEmptyDOMElement();
  });

  it("surfaces a 403 ApiError with the INSUFFICIENT SCOPE title", async () => {
    renderBanner();
    const err = new ApiError(403, "needs the prove scope");
    err.requiredScope = "prove";
    err.grantedScopes = ["read", "verify"];
    await emitMutationError(err);

    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(screen.getByText(/INSUFFICIENT SCOPE/)).toBeInTheDocument();
    expect(screen.getByText(/needs the prove scope/)).toBeInTheDocument();
    // requiredScope + grantedScopes render inside the same "requires scope:"
    // line — match the granted list which is unique to that row.
    expect(screen.getByText(/read, verify/)).toBeInTheDocument();
  });

  it("shows NOT AUTHENTICATED for a 401", async () => {
    renderBanner();
    await emitMutationError(new ApiError(401, "no api key"));
    expect(await screen.findByText(/NOT AUTHENTICATED/)).toBeInTheDocument();
  });

  it("ignores non-401/403 ApiErrors", async () => {
    renderBanner();
    await emitMutationError(new ApiError(500, "internal error"));
    // Give the subscribe handler a tick; nothing should render.
    await new Promise((r) => setTimeout(r, 10));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("ignores non-ApiError throwables", async () => {
    renderBanner();
    await emitMutationError(new Error("plain error"));
    await new Promise((r) => setTimeout(r, 10));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("joins an array requiredScope with ' / '", async () => {
    renderBanner();
    const err = new ApiError(403, "scope");
    err.requiredScope = ["ingest", "commit"];
    await emitMutationError(err);
    expect(await screen.findByText(/ingest \/ commit/)).toBeInTheDocument();
  });

  it("dismisses when the ✕ button is clicked", async () => {
    renderBanner();
    await emitMutationError(new ApiError(403, "scope"));
    await screen.findByRole("alert");
    await userEvent.click(screen.getByRole("button", { name: /dismiss/i }));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});
