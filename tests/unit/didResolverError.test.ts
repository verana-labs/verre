import { Resolver } from 'did-resolver'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// Mock didwebvh-ts *before* importing anything that transitively imports it.
// `vi.mock` is hoisted, so the mock factory is wrapped in `vi.hoisted` to
// ensure the `resolveDIDMock` reference is available by the time the module
// registry rewires the import.
const { resolveDIDMock } = vi.hoisted(() => ({ resolveDIDMock: vi.fn() }))
vi.mock('didwebvh-ts', () => ({
  resolveDID: resolveDIDMock,
}))

import { baseResolver } from '../../src/libraries/did-resolver'
import { resolveDID, TrustResolutionOutcome } from '../../src'
import { resolverInstance } from '../../src/libraries'
import { TrustErrorCode } from '../../src/types'

// Use a distinct DID per test case so the module-level `resolverInstance`
// cache from `libraries/did-resolver.ts` cannot leak a prior result into a
// later assertion (the cache is keyed by bare DID).
const DID_OK = 'did:webvh:QmSCID:ok.example.com'
const DID_INVALID = 'did:webvh:QmSCID:invalid.example.com'
const DID_INVALID_SCID = 'did:webvh:QmSCID:invalid-scid.example.com'
const DID_NOT_FOUND = 'did:webvh:QmSCID:not-found.example.com'
const DID_THROW_ENOTFOUND = 'did:webvh:QmSCID:throw-enotfound.example.com'
const DID_THROW_VALIDATION = 'did:webvh:QmSCID:throw-validation.example.com'
const DID_THROW_UNKNOWN = 'did:webvh:QmSCID:throw-unknown.example.com'
const DID_RESOLVE_INVALID = 'did:webvh:QmSCID:resolve-invalid.example.com'
const DID_RESOLVE_NOT_FOUND = 'did:webvh:QmSCID:resolve-not-found.example.com'

describe('webVhDidResolver wrapper — faithful error mapping', () => {
  afterEach(() => {
    resolveDIDMock.mockReset()
  })

  it('surfaces a successful resolution unchanged', async () => {
    const doc = { id: DID_OK, service: [] }
    resolveDIDMock.mockResolvedValue({ doc, meta: {} })

    const result = await baseResolver.resolve(DID_OK)

    expect(result.didResolutionMetadata.error).toBeUndefined()
    expect(result.didDocument).toEqual(doc)
  })

  it('maps INVALID_DID from didwebvh-ts to invalidDid and preserves problemDetails.detail', async () => {
    // Real-world payload observed on did:webvh:…:avatar.vs.hologram.zone
    resolveDIDMock.mockResolvedValue({
      doc: null,
      meta: {
        error: 'INVALID_DID',
        problemDetails: {
          type: 'https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID',
          title: 'The resolved DID is invalid.',
          detail: "Hash chain broken at '2-QmPAFJ9dGWY4yNG5aH13a1cHXcNgU27BTcekSnoBNeGn3h'",
        },
      },
    })

    const result = await baseResolver.resolve(DID_INVALID)

    expect(result.didResolutionMetadata.error).toBe('invalidDid')
    // The problemDetails.detail must survive onto the resolution metadata so
    // downstream callers can log / display the underlying cause.
    expect((result.didResolutionMetadata as { message?: string }).message).toContain('Hash chain broken at')
    // didDocumentMetadata must carry the full `meta` object from didwebvh-ts.
    expect(
      (result.didDocumentMetadata as { problemDetails?: { detail?: string } }).problemDetails?.detail,
    ).toContain('Hash chain broken at')
    expect(result.didDocument).toBeNull()
  })

  it('maps other INVALID_* codes to invalidDid (prefix rule)', async () => {
    resolveDIDMock.mockResolvedValue({
      doc: null,
      meta: { error: 'INVALID_SCID' },
    })

    const result = await baseResolver.resolve(DID_INVALID_SCID)

    expect(result.didResolutionMetadata.error).toBe('invalidDid')
  })

  it('maps an explicit NOT_FOUND code to notFound', async () => {
    resolveDIDMock.mockResolvedValue({
      doc: null,
      meta: { error: 'NOT_FOUND' },
    })

    const result = await baseResolver.resolve(DID_NOT_FOUND)

    expect(result.didResolutionMetadata.error).toBe('notFound')
  })

  it('classifies thrown fetch failures (ENOTFOUND / 404) as notFound via message heuristic', async () => {
    resolveDIDMock.mockRejectedValue(new Error('getaddrinfo ENOTFOUND nope.example.com'))

    const result = await baseResolver.resolve(DID_THROW_ENOTFOUND)

    expect(result.didResolutionMetadata.error).toBe('notFound')
    expect((result.didResolutionMetadata as { message?: string }).message).toContain('ENOTFOUND')
  })

  it('classifies thrown validation errors as invalidDid via message heuristic', async () => {
    resolveDIDMock.mockRejectedValue(new Error('Invalid witness proof on version 2'))

    const result = await baseResolver.resolve(DID_THROW_VALIDATION)

    expect(result.didResolutionMetadata.error).toBe('invalidDid')
  })

  it('falls back to internalError for unrecognised thrown errors', async () => {
    resolveDIDMock.mockRejectedValue(new Error('something totally unexpected happened'))

    const result = await baseResolver.resolve(DID_THROW_UNKNOWN)

    expect(result.didResolutionMetadata.error).toBe('internalError')
  })
})

describe('retrieveDidDocument — propagate INVALID vs NOT_FOUND via resolveDID()', () => {
  // These tests stub Resolver.prototype.resolve directly so they do not depend
  // on didwebvh-ts or the webvh wrapper behaviour — they pin the contract
  // that `retrieveDidDocument` itself honours resolution metadata.
  beforeEach(() => {
    // Clear the module-level resolver cache so the per-DID results used in
    // the wrapper suite above do not leak into these assertions.
    resolverInstance.clear()
    vi.restoreAllMocks()
  })

  afterEach(() => {
    resolverInstance.clear()
    vi.restoreAllMocks()
  })

  it('raises INVALID (not NOT_FOUND) when the resolver reports invalidDid with a problem detail', async () => {
    vi.spyOn(Resolver.prototype, 'resolve').mockResolvedValue({
      didDocument: null,
      didResolutionMetadata: {
        error: 'invalidDid',
        message: "Hash chain broken at '2-Qm…'",
      },
      didDocumentMetadata: {
        problemDetails: {
          type: 'https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID',
          title: 'The resolved DID is invalid.',
          detail: "Hash chain broken at '2-Qm…'",
        },
      },
    } as unknown as Awaited<ReturnType<Resolver['resolve']>>)

    const resolution = await resolveDID(DID_RESOLVE_INVALID, { verifiablePublicRegistries: [] })

    expect(resolution.verified).toBe(false)
    expect(resolution.outcome).toBe(TrustResolutionOutcome.INVALID)
    expect(resolution.metadata?.errorCode).toBe(TrustErrorCode.INVALID)
    // The diagnostic detail must propagate into the user-visible error message.
    expect(resolution.metadata?.errorMessage).toContain('Hash chain broken at')
  })

  it('still raises NOT_FOUND when the resolver returns no document and no invalidDid error', async () => {
    vi.spyOn(Resolver.prototype, 'resolve').mockResolvedValue({
      didDocument: null,
      didResolutionMetadata: { error: 'notFound' },
      didDocumentMetadata: {},
    } as unknown as Awaited<ReturnType<Resolver['resolve']>>)

    const resolution = await resolveDID(DID_RESOLVE_NOT_FOUND, { verifiablePublicRegistries: [] })

    expect(resolution.verified).toBe(false)
    expect(resolution.metadata?.errorCode).toBe(TrustErrorCode.NOT_FOUND)
  })
})
