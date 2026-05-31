import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import StatCards from "./StatCards";
import { renderWithSkin } from "../__tests__/render";

// AnimatedNumber tweens — stub it to render the final value synchronously
// so we can assert on the displayed number without waiting on animation.
vi.mock("./AnimatedNumber", () => ({
  default: ({ value }: { value: number }) => <span>{value}</span>,
}));

describe("<StatCards>", () => {
  it("renders one card per stat with its label", () => {
    renderWithSkin(
      <StatCards
        cards={[
          { label: "NODES", value: 3 },
          { label: "PROOFS", value: 10 },
        ]}
        onRefetch={vi.fn()}
      />,
    );
    expect(screen.getByText("NODES")).toBeInTheDocument();
    expect(screen.getByText("PROOFS")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("10")).toBeInTheDocument();
  });

  it("renders raw string values verbatim (no AnimatedNumber)", () => {
    renderWithSkin(
      <StatCards cards={[{ label: "UPTIME", value: "1h 23m", raw: true }]} onRefetch={vi.fn()} />,
    );
    expect(screen.getByText("1h 23m")).toBeInTheDocument();
  });

  it("calls onRefetch when a card is clicked", async () => {
    const onRefetch = vi.fn();
    renderWithSkin(
      <StatCards cards={[{ label: "NODES", value: 1 }]} onRefetch={onRefetch} />,
    );
    await userEvent.click(screen.getByRole("button"));
    expect(onRefetch).toHaveBeenCalledTimes(1);
  });

  it("renders no cards when the array is empty", () => {
    renderWithSkin(<StatCards cards={[]} onRefetch={vi.fn()} />);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
