import { describe, expect, it } from 'vitest'

import { resolveTrustRegistry } from '../../src/resolver/didValidator'
import { TrustError } from '../../src/utils/trustError'
import { TrustErrorCode, TrustResolutionOutcome, type VerifiablePublicRegistry } from '../../src/types'

const TESTNET: VerifiablePublicRegistry = {
  id: 'vpr:verana:vna-testnet-1',
  baseUrls: ['https://idx.testnet.verana.network/verana'],
  production: true,
}

const DEVNET: VerifiablePublicRegistry = {
  id: 'vpr:verana:vna-devnet-1',
  baseUrls: ['https://idx.devnet.verana.network/verana'],
  production: false,
}

describe('resolveTrustRegistry — REGISTRY_NOT_CONFIGURED guard', () => {
  it('throws REGISTRY_NOT_CONFIGURED when a vpr: refUrl matches no configured registry', () => {
    // The scenario that produced the original `null/verana:vna-testnet-1/perm/v1/list?…`
    // URL: a credential references the testnet registry, but the operator
    // forgot to add testnet to `VPR_REGISTRIES`.
    expect(() => resolveTrustRegistry('vpr:verana:vna-testnet-1/cs/js/170', [DEVNET])).toThrow(TrustError)

    try {
      resolveTrustRegistry('vpr:verana:vna-testnet-1/cs/js/170', [DEVNET])
    } catch (e) {
      const err = e as TrustError
      expect(err.metadata.errorCode).toBe(TrustErrorCode.REGISTRY_NOT_CONFIGURED)
      expect(err.message).toContain('vpr:verana:vna-testnet-1')
      // The id portion (no path) should appear so operators see exactly which
      // registry is missing from their config.
      expect(err.message).toContain("matches 'vpr:verana:vna-testnet-1'")
    }
  })

  it('also throws when verifiablePublicRegistries is undefined or empty', () => {
    expect(() => resolveTrustRegistry('vpr:verana:vna-testnet-1/cs/js/170', undefined)).toThrow(TrustError)
    expect(() => resolveTrustRegistry('vpr:verana:vna-testnet-1/cs/js/170', [])).toThrow(TrustError)
  })

  it('rewrites a vpr: refUrl to the matched registry baseUrl and returns trust metadata', () => {
    // Happy path mirroring the resolver container's runtime config: the
    // `vpr:verana:vna-testnet-1/cs/js/170` reference resolves into a real
    // HTTPS URL via the matched registry's `baseUrls[0]`.
    const result = resolveTrustRegistry('vpr:verana:vna-testnet-1/cs/js/170', [TESTNET, DEVNET])

    expect(result.schemaUrl).toBe('https://idx.testnet.verana.network/verana/cs/js/170')
    expect(result.trustRegistry).toBe('https://idx.testnet.verana.network/verana')
    expect(result.schemaId).toBe('170')
    expect(result.outcome).toBe(TrustResolutionOutcome.VERIFIED)
    expect(result.registry?.id).toBe(TESTNET.id)
  })

  it('marks non-production registries as VERIFIED_TEST', () => {
    const result = resolveTrustRegistry('vpr:verana:vna-devnet-1/cs/js/170', [TESTNET, DEVNET])
    expect(result.outcome).toBe(TrustResolutionOutcome.VERIFIED_TEST)
  })

  it('does NOT throw for non-vpr refUrls that simply do not match any registry', () => {
    // Backward-compatible behaviour: if the credential references an HTTPS
    // schema URL directly (no `vpr:` scheme), the legacy fallthrough is fine
    // — `new URL(refUrl)` produces a real origin and pathname, so downstream
    // code keeps working even without a matching registry. Only the `vpr:`
    // scheme triggers the misconfig guard.
    const result = resolveTrustRegistry('https://example.com/registry/cs/js/170', [])

    expect(result.outcome).toBe(TrustResolutionOutcome.NOT_TRUSTED)
    expect(result.schemaUrl).toBe('https://example.com/registry/cs/js/170')
    expect(result.trustRegistry).toBe('https://example.com/registry')
    expect(result.schemaId).toBe('170')
    expect(result.registry).toBeUndefined()
  })
})
