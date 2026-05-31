import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import HashReveal from "./HashReveal";

describe("<HashReveal>", () => {
  it("renders nothing when hash is null", () => {
    const { container } = render(<HashReveal hash={null} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders the hash and the default BLAKE3_DIGEST label", () => {
    const hash = "ff".repeat(32);
    render(<HashReveal hash={hash} />);
    expect(screen.getByText(hash)).toBeInTheDocument();
    expect(screen.getByText("BLAKE3_DIGEST")).toBeInTheDocument();
  });

  it("renders a custom label when supplied", () => {
    render(<HashReveal hash="aa" label="CONTENT_HASH" />);
    expect(screen.getByText("CONTENT_HASH")).toBeInTheDocument();
  });

  it("exposes a 'BLAKE3 hash' aria-label on the wrapper", () => {
    render(<HashReveal hash="aa" />);
    expect(screen.getByLabelText("BLAKE3 hash")).toBeInTheDocument();
  });
});
