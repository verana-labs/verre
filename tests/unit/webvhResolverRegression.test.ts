import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { baseResolver } from '../../src/libraries/did-resolver.js'

// ---------------------------------------------------------------------------
// Regression test: did:webvh hash-chain validation must succeed for a real
// 54-entry log captured from `did:webvh:Qm…:organization.vs.hologram.zone`.
//
// `didwebvh-ts@2.7.3` introduced a bug in the hash-chain check that made
// every multi-entry webvh log fail with `"Hash chain broken at '2-Qm…'"`,
// regardless of input. The regression hunk replaced the spec-mandated
// `versionId: PLACEHOLDER` slot with `versionId: resolutionLog[i-1].versionId`
// when recomputing each entry's hash, which is incorrect — the placeholder
// is the input the original publisher hashed, so any value other than the
// placeholder will mismatch by design.
//
// The fix is to pin `didwebvh-ts` to `2.7.2` until the upstream bug is
// addressed. This test bakes a real, known-good log into the repo so any
// future bump that re-introduces the same class of regression fails loudly
// in CI rather than at runtime against testnet.
// ---------------------------------------------------------------------------

const FIXTURE_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  'fixtures',
  'organization.vs.hologram.zone.did.jsonl',
)

const FIXTURE_DID =
  'did:webvh:QmRhJBzLMF6L3REha9xFpLgxui9X5tFm4TDxHoEHpA8Kpr:organization.vs.hologram.zone'

const FIXTURE_LOG_URL = 'https://organization.vs.hologram.zone/.well-known/did.jsonl'

describe('did:webvh resolver — hash-chain validation regression guard', () => {
  const originalFetch = globalThis.fetch

  beforeEach(() => {
    // Stub `fetch` so the test never touches the network. The fixture is
    // returned for the well-known did.jsonl URL; any other URL returns 404
    // so an accidental fetch (e.g. trying to dereference a service) does
    // not silently succeed via the real network.
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      if (url === FIXTURE_LOG_URL) {
        const body = readFileSync(FIXTURE_PATH, 'utf-8')
        return new Response(body, {
          status: 200,
          headers: { 'content-type': 'text/jsonl; charset=utf-8' },
        })
      }
      return new Response('not found', { status: 404 })
    }) as typeof fetch
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
    vi.restoreAllMocks()
  })

  it('resolves a real 54-entry did:webvh log and reports `deactivated: false`', async () => {
    const result = await baseResolver.resolve(FIXTURE_DID)

    // The signature of failure under the 2.7.3 regression: `didDocument`
    // is null and `didResolutionMetadata.error` is `invalidDid` with a
    // `Hash chain broken at '2-Qm…'` problem detail. Asserting positively
    // on `didDocument` and the `versionId` makes both the symptom and a
    // happy path explicit so a future regression can't sneak past.
    expect(result.didResolutionMetadata?.error).toBeUndefined()
    expect(result.didDocument).toBeTruthy()
    expect(result.didDocument?.id).toBe(FIXTURE_DID)

    const meta = result.didDocumentMetadata as { versionId?: string; deactivated?: boolean } | undefined
    expect(meta?.deactivated).toBe(false)
    // The fixture currently has 54 entries; the latest versionId starts
    // with `55-` (entry index N produces versionId `N+1-…`) — assert just
    // the prefix so re-capturing the fixture later does not require
    // updating the hash.
    expect(meta?.versionId).toMatch(/^55-Qm/)
  })

  it('emits an `invalidDid` error (not `notFound`) if the JSONL log itself is corrupted', async () => {
    // Sanity check that the resolver's error-mapping wired up in
    // `did-resolver.ts` still distinguishes a malformed log from a missing
    // one. This is the partner test to the regression case above: when
    // hash-chain validation legitimately fails, the W3C error code must
    // be `invalidDid` (not `notFound`), so downstream consumers can tell
    // "DID does not exist" apart from "DID exists but log is invalid".
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      if (url === FIXTURE_LOG_URL) {
        const body = readFileSync(FIXTURE_PATH, 'utf-8')
        // Truncate the second JSONL entry so the chain is genuinely broken.
        const lines = body.split('\n')
        if (lines.length > 2) {
          lines[1] = lines[1].slice(0, Math.floor(lines[1].length / 2))
        }
        return new Response(lines.join('\n'), {
          status: 200,
          headers: { 'content-type': 'text/jsonl; charset=utf-8' },
        })
      }
      return new Response('not found', { status: 404 })
    }) as typeof fetch

    const result = await baseResolver.resolve(FIXTURE_DID)
    expect(result.didDocument).toBeNull()
    // Either `invalidDid` (preferred — log present but invalid) or
    // `internalError` (parse-time exception). `notFound` would be wrong
    // because the log clearly exists.
    expect(['invalidDid', 'internalError']).toContain(result.didResolutionMetadata?.error)
  })
})
