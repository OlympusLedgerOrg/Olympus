import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import SkinSelector from "./SkinSelector";
import { renderWithSkin } from "../__tests__/render";

beforeEach(() => {
  localStorage.clear();
});

afterEach(() => {
  localStorage.clear();
});

describe("<SkinSelector>", () => {
  it("renders one button per registered skin", () => {
    renderWithSkin(<SkinSelector />);
    const buttons = screen.getAllByRole("button");
    // At least the three known skins (basic, terminal, glitch); guard against
    // future additions silently dropping below that floor.
    expect(buttons.length).toBeGreaterThanOrEqual(3);
  });

  it("marks exactly one button aria-pressed=true (the active skin)", () => {
    renderWithSkin(<SkinSelector />);
    const pressed = screen.getAllByRole("button").filter(
      (b) => b.getAttribute("aria-pressed") === "true",
    );
    expect(pressed).toHaveLength(1);
  });

  it("clicking a different skin updates aria-pressed", async () => {
    renderWithSkin(<SkinSelector />);
    const inactive = screen.getAllByRole("button").find(
      (b) => b.getAttribute("aria-pressed") === "false",
    );
    expect(inactive).toBeDefined();
    await userEvent.click(inactive!);
    expect(inactive).toHaveAttribute("aria-pressed", "true");
  });

  it("clicking persists the selection to localStorage (cross-reload memory)", async () => {
    renderWithSkin(<SkinSelector />);
    const inactive = screen.getAllByRole("button").find(
      (b) => b.getAttribute("aria-pressed") === "false",
    );
    expect(inactive).toBeDefined();
    await userEvent.click(inactive!);
    expect(localStorage.getItem("olympus_skin")).not.toBeNull();
  });
});
