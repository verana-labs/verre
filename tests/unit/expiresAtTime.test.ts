import { describe, expect, it } from 'vitest'

import { earliestBoundary } from '../../src/resolver/didValidator'

describe('earliestBoundary', () => {
  it('returns the earliest of the credential and participant boundaries', () => {
    expect(
      earliestBoundary([
        '2030-01-01T00:00:00.000Z',
        '2029-01-01T00:00:00.000Z',
        '2028-06-01T00:00:00.000Z',
        '2027-01-31T23:59:59.000Z',
      ]),
    ).toBe('2027-01-31T23:59:59.000Z')
  })

  it('returns null when no boundary exists', () => {
    expect(earliestBoundary([undefined, null, undefined, null])).toBeNull()
  })
})
