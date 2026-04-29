import { readFileSync } from 'node:fs'
import { describe, it, expect } from 'vitest'

// didwebvh-ts >=2.7.3 is spec-compliant but rejects DIDs already minted on
// Verana testnet by older (non-compliant) issuers. Until those DIDs are
// re-issued, verre must stay on 2.7.2 to keep resolution working. This test
// fails CI if anyone bumps the dep without coordinating the re-issue.
describe('didwebvh-ts version pin', () => {
  it('must be pinned exactly to 2.7.2', () => {
    const pkg = JSON.parse(readFileSync('package.json', 'utf-8'))
    expect(pkg.dependencies['didwebvh-ts']).toBe('2.7.2')
  })
})
