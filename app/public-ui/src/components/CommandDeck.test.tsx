import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import CommandDeck from "./CommandDeck";
import { renderWithSkin } from "../__tests__/render";

describe("<CommandDeck>", () => {
  it("renders the four command cards with their codes", () => {
    renderWithSkin(<CommandDeck activeTab="hash" onSelect={vi.fn()} />);
    expect(screen.getByText("VERIFY")).toBeInTheDocument();
    expect(screen.getByText("AUDIT")).toBeInTheDocument();
    expect(screen.getByText("AUDIT_R")).toBeInTheDocument();
    expect(screen.getByText("REDACT")).toBeInTheDocument();
  });

  it("marks the active tab aria-pressed=true and the others false", () => {
    renderWithSkin(<CommandDeck activeTab="audit" onSelect={vi.fn()} />);
    const buttons = screen.getAllByRole("button");
    const pressed = buttons.filter((b) => b.getAttribute("aria-pressed") === "true");
    expect(pressed).toHaveLength(1);
    expect(pressed[0].textContent).toMatch(/AUDIT/);
  });

  it("calls onSelect with the tab id when a card is clicked", async () => {
    const onSelect = vi.fn();
    renderWithSkin(<CommandDeck activeTab="hash" onSelect={onSelect} />);
    const auditCard = screen.getAllByRole("button").find((b) => b.textContent?.includes("AUDIT"));
    await userEvent.click(auditCard!);
    expect(onSelect).toHaveBeenCalledWith("audit");
  });

  it("renders the descriptions for each command", () => {
    renderWithSkin(<CommandDeck activeTab="hash" onSelect={vi.fn()} />);
    expect(screen.getByText(/Paste a BLAKE3 hash/i)).toBeInTheDocument();
    expect(screen.getByText(/Drop a Groth16 proof bundle/i)).toBeInTheDocument();
    expect(screen.getByText(/Drop the redacted file/i)).toBeInTheDocument();
  });
});
