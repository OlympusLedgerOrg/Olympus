import { describe, it, expect } from 'vitest'

// Smoke test that just proves the vitest harness loads. Real tests will
// land alongside PR C+ when coverage targets are set.
describe('vitest smoke', () => {
  it('runs', () => {
    expect(1 + 1).toBe(2)
  })
})
