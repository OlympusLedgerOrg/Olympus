import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/api", () => ({
  apiFetch: vi.fn(),
}));

import { apiFetch } from "../lib/api";
import OnboardPage from "./OnboardPage";

const mockedApiFetch = vi.mocked(apiFetch);

function renderOnboard() {
  return render(
    <MemoryRouter>
      <OnboardPage />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  mockedApiFetch.mockReset();
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<OnboardPage>", () => {
  it("renders the registration form by default", () => {
    renderOnboard();
    expect(screen.getByPlaceholderText(/you@example.com/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/at least 12 characters/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/repeat password/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /create|register|submit/i })).toBeInTheDocument();
  });

  it("rejects mismatched passwords without calling the API", async () => {
    renderOnboard();
    await userEvent.type(screen.getByPlaceholderText(/you@example.com/i), "u@x.com");
    const pwFields = [
      screen.getByPlaceholderText(/at least 12 characters/i),
      screen.getByPlaceholderText(/repeat password/i),
    ];
    await userEvent.type(pwFields[0], "longenoughpassword123");
    await userEvent.type(pwFields[1], "different-confirmation");
    await userEvent.click(screen.getByRole("button", { name: /create|register|submit/i }));
    expect(await screen.findByText(/do not match/i)).toBeInTheDocument();
    expect(mockedApiFetch).not.toHaveBeenCalled();
  });

  it("rejects passwords shorter than 12 chars", async () => {
    renderOnboard();
    await userEvent.type(screen.getByPlaceholderText(/you@example.com/i), "u@x.com");
    const pwFields = [
      screen.getByPlaceholderText(/at least 12 characters/i),
      screen.getByPlaceholderText(/repeat password/i),
    ];
    await userEvent.type(pwFields[0], "shortpw");
    await userEvent.type(pwFields[1], "shortpw");
    await userEvent.click(screen.getByRole("button", { name: /create|register|submit/i }));
    expect(await screen.findByText(/at least 12 characters/i)).toBeInTheDocument();
    expect(mockedApiFetch).not.toHaveBeenCalled();
  });

  it("submits /auth/register and renders the issued API key on success", async () => {
    mockedApiFetch.mockResolvedValue({ api_key: "oly_minted_key", user_id: "u-42" });
    renderOnboard();
    await userEvent.type(screen.getByPlaceholderText(/you@example.com/i), "user@example.com");
    const pwFields = [
      screen.getByPlaceholderText(/at least 12 characters/i),
      screen.getByPlaceholderText(/repeat password/i),
    ];
    await userEvent.type(pwFields[0], "longenoughpassword");
    await userEvent.type(pwFields[1], "longenoughpassword");
    await userEvent.click(screen.getByRole("button", { name: /create|register|submit/i }));

    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledTimes(1));
    const [path, init] = mockedApiFetch.mock.calls[0];
    expect(path).toBe("/auth/register");
    const body = JSON.parse(String(init?.body));
    expect(body.email).toBe("user@example.com");
    expect(body.scopes).toEqual(["ingest", "verify"]);
    expect(body.name).toBe("user"); // derived from email local-part

    expect(await screen.findByText(/ACCESS GRANTED/i)).toBeInTheDocument();
    expect(screen.getByText("oly_minted_key")).toBeInTheDocument();
    // user_id is rendered alongside a `<strong>USER ID</strong>` label, so
    // the literal "u-42" is a sibling text node — match leniently.
    expect(screen.getByText(/u-42/)).toBeInTheDocument();
  });

  it("surfaces an error message when /auth/register rejects", async () => {
    mockedApiFetch.mockRejectedValue(new Error("Email already taken"));
    renderOnboard();
    await userEvent.type(screen.getByPlaceholderText(/you@example.com/i), "user@example.com");
    const pwFields = [
      screen.getByPlaceholderText(/at least 12 characters/i),
      screen.getByPlaceholderText(/repeat password/i),
    ];
    await userEvent.type(pwFields[0], "longenoughpassword");
    await userEvent.type(pwFields[1], "longenoughpassword");
    await userEvent.click(screen.getByRole("button", { name: /create|register|submit/i }));
    expect(await screen.findByText(/Email already taken/i)).toBeInTheDocument();
    expect(screen.queryByText(/ACCESS GRANTED/i)).not.toBeInTheDocument();
  });
});
