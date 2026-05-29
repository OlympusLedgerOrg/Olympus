import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SkinProvider } from "../skins/SkinProvider";

vi.mock("../lib/storage", () => ({
  hasStoredAdminKey: vi.fn(),
}));

// Heavy / animated subcomponents are excluded from coverage in phase 4 and
// would force big mock surfaces here — stub them to keep the test isolated
// to Layout's own nav/route logic.
vi.mock("./GlyphRain", () => ({ default: () => <div data-testid="glyph-rain" /> }));
vi.mock("./CrtOverlay", () => ({ default: () => <div data-testid="crt-overlay" /> }));
vi.mock("./GlitchMentorPopups", () => ({ default: () => <div data-testid="mentor" /> }));
vi.mock("./SkylineBackdrop", () => ({ default: () => <div data-testid="skyline" /> }));
vi.mock("./SkinSelector", () => ({ default: () => <div data-testid="skin-selector" /> }));
vi.mock("./WhoAmIChip", () => ({ default: () => <div data-testid="whoami" /> }));

import { hasStoredAdminKey } from "../lib/storage";
import Layout from "./Layout";

const mockedHasStoredAdminKey = vi.mocked(hasStoredAdminKey);

function renderLayout(path = "/", children: React.ReactNode = <div>child content</div>) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <SkinProvider>
        <Layout>{children}</Layout>
      </SkinProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  mockedHasStoredAdminKey.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<Layout>", () => {
  it("renders the OLYMPUS_PROTOCØL header logo + footer + children", () => {
    mockedHasStoredAdminKey.mockReturnValue(false);
    renderLayout("/", <div>page body</div>);
    // The literal "OLYMPUS_PROTOCØL" appears twice: header logo and footer
    // copyright. Both are correct; assert at least one is present.
    expect(screen.getAllByText(/OLYMPUS_PROTOCØL/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/PROJECT_MAYHEM/i)).toBeInTheDocument();
    expect(screen.getByText(/page body/)).toBeInTheDocument();
  });

  it("renders only VERIFY in the nav when no admin key is stored", () => {
    mockedHasStoredAdminKey.mockReturnValue(false);
    renderLayout("/");
    expect(screen.getByRole("link", { name: /VERIFY/i })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /^KEYS$/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /^USERS$/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /^SBTs$/i })).not.toBeInTheDocument();
  });

  it("reveals KEYS / USERS / SBTs links when an admin key is stored", () => {
    mockedHasStoredAdminKey.mockReturnValue(true);
    renderLayout("/");
    expect(screen.getByRole("link", { name: /^KEYS$/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /^USERS$/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /^SBTs$/i })).toBeInTheDocument();
  });

  it("highlights the active nav link based on the current route", () => {
    mockedHasStoredAdminKey.mockReturnValue(true);
    renderLayout("/keys");
    const keysLink = screen.getByRole("link", { name: /^KEYS$/i });
    // Active link has the accent colour applied inline.
    expect(keysLink).toHaveStyle({ color: "rgb(0, 255, 65)" });
    const verifyLink = screen.getByRole("link", { name: /VERIFY/i });
    expect(verifyLink).not.toHaveStyle({ color: "rgb(0, 255, 65)" });
  });

  it("renders the WhoAmIChip + SkinSelector stubs in the header", () => {
    mockedHasStoredAdminKey.mockReturnValue(true);
    renderLayout("/");
    expect(screen.getByTestId("whoami")).toBeInTheDocument();
    expect(screen.getByTestId("skin-selector")).toBeInTheDocument();
  });

  it("shows the ENCRYPTED status pip at the right of the header", () => {
    mockedHasStoredAdminKey.mockReturnValue(false);
    renderLayout("/");
    expect(screen.getByText(/ENCRYPTED/)).toBeInTheDocument();
  });
});
