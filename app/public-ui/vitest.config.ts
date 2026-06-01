import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// Vitest config kept separate from vite.config.ts so the prod build doesn't
// pull in vitest types. Run with `pnpm test` / `pnpm coverage`.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/setupTests.ts'],
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'json-summary'],
      reportsDirectory: './coverage',
      // Files excluded from the coverage denominator. Two categories:
      //   1. Not behavioural code (type stubs, test infra, the root
      //      bootstrap file that just calls ReactDOM.createRoot).
      //   2. Visual-only / animation-driven components that render motion,
      //      chrome, or skin theming with no behaviour a unit test could
      //      meaningfully assert. Excluded NOT because they're untested
      //      out of laziness, but because forcing coverage on animation
      //      timing and framer-motion props is busywork that buys no
      //      correctness signal. See issue #1079.
      //   3. WASM/Audio entry points whose only "behaviour" is calling
      //      browser APIs jsdom cannot mock soundly (Audio() construction,
      //      BLAKE3 WASM init via dynamic import). Their consumers
      //      (FileHasher, useRedactionAudit, etc.) are covered via mocks.
      exclude: [
        // Category 1 — not behavioural code
        'src/**/*.d.ts',
        'src/main.tsx',
        'src/setupTests.ts',
        'src/vite-env.d.ts',
        'src/**/*.test.{ts,tsx}',
        'src/**/*.spec.{ts,tsx}',
        'src/**/__tests__/**',
        'src/lib/types.ts',
        'src/skins/types.ts',
        // App.tsx is the router root — every page test exercises it
        // transitively, but it has no isolated behaviour worth direct
        // coverage.
        'src/App.tsx',

        // Category 2 — visual-only / animation chrome
        'src/components/GlyphRain.tsx',
        'src/components/CrtOverlay.tsx',
        'src/components/SkylineBackdrop.tsx',
        'src/components/TiltContainer.tsx',
        'src/components/LoadingSplash.tsx',
        'src/components/GlitchMentorPopups.tsx',
        'src/skins/SkinProvider.tsx',
        'src/skins/SkinContext.ts',
        'src/skins/registry.ts',

        // Category 3 — browser-API entry points whose only "behaviour" is
        // calling APIs jsdom can't mock soundly (Audio() construction).
        // BLAKE3 stays IN the denominator: ensureInit's CSP-error mapping,
        // the all-zero ABI guards in hashBytes/hashFile, and the
        // hasher.free() cleanup are ledger-safety invariants and must be
        // covered. The tests in src/lib/blake3.test.ts mock the underlying
        // blake3-wasm exports so the control flow is exercised without
        // loading the actual WASM binary.
        'src/lib/audio.ts',
      ],
      // Coverage thresholds — match the v1.0 quality gate from issue
      // #1079. Vitest exits non-zero when any of these drop below the
      // configured floor, so the `.github/workflows/coverage.yml`
      // `frontend coverage (vitest)` job becomes a hard CI gate without
      // needing a separate threshold-check step.
      //
      // Lines/statements are the headline 85% target. Branches at 80% is
      // strict enough to catch missing else-paths without thrashing.
      // Functions at 70% reflects that v8 counts every tiny inline arrow
      // (onChange handlers, useCallback closures, switch-arm helpers)
      // disproportionately — chasing the last 15% of function coverage is
      // busywork that doesn't translate to behavioural coverage.
      thresholds: {
        lines: 85,
        functions: 70,
        branches: 80,
        statements: 85,
      },
    },
  },
})
