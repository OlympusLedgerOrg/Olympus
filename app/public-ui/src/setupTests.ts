import "@testing-library/jest-dom/vitest";

// Node >= 25 defines `localStorage` and `sessionStorage` on `globalThis` as
// lazy accessors that return `undefined` unless the process was started with
// `--localstorage-file`. Vitest's jsdom environment copies window properties
// onto the test global only when the name is absent there or on its own
// allowlist, and these two are on neither through vitest 4.1.x — so Node's
// undefined global wins over jsdom's working Storage, and every test that
// touches storage dies with "Cannot read properties of undefined (reading
// 'clear')". CI pins Node 22.19, which has no such global, so this only ever
// bit developers — and then only on the newest Node.
//
// jsdom's own Storage survives on the environment object vitest exposes as
// `globalThis.jsdom`, so put it back when Node shadowed it. On Node <= 24 the
// names are absent and vitest already installed these same objects, so this is
// a no-op there. Vitest 5 fixes the environment itself (#10293); this guard can
// go when the toolchain is on that line.
const nodeShadowed = globalThis as typeof globalThis & {
  localStorage?: Storage;
  sessionStorage?: Storage;
  jsdom?: { window: Window };
};

const jsdomWindow = nodeShadowed.jsdom?.window;
if (jsdomWindow) {
  if (nodeShadowed.localStorage === undefined) {
    Object.defineProperty(globalThis, "localStorage", {
      value: jsdomWindow.localStorage,
      configurable: true,
      writable: true,
    });
  }
  if (nodeShadowed.sessionStorage === undefined) {
    Object.defineProperty(globalThis, "sessionStorage", {
      value: jsdomWindow.sessionStorage,
      configurable: true,
      writable: true,
    });
  }
}
