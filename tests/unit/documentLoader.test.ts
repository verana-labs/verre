import jsonld from '@digitalcredentials/jsonld'
import { Resolver } from 'did-resolver'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { createDocumentLoader, DEFAULT_CONTEXTS } from '../../src/libraries'

const CREDENTIALS_V2_URL = 'https://www.w3.org/ns/credentials/v2'

const unusedResolver = {
  resolve: async () => {
    throw new Error('the resolver must not be consulted for a bundled context')
  },
} as unknown as Resolver

describe('document loader', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('serves the VC Data Model 2.0 context from the bundled contexts, without network access', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const loader = createDocumentLoader(unusedResolver)

    const { document, documentUrl } = await loader(CREDENTIALS_V2_URL)

    expect(documentUrl).toBe(CREDENTIALS_V2_URL)
    expect(document).toBe(DEFAULT_CONTEXTS[CREDENTIALS_V2_URL])
    const context = document['@context'] as Record<string, unknown>
    expect(context.VerifiableCredential).toBeDefined()
    expect(context.VerifiablePresentation).toBeDefined()
    expect(context.DataIntegrityProof).toBeDefined()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('canonicalizes a VC Data Model 2.0 credential offline', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const nquads = await jsonld.canonize(
      {
        '@context': [CREDENTIALS_V2_URL],
        id: 'https://example.com/credentials/1',
        type: ['VerifiableCredential'],
        issuer: 'did:example:issuer',
        validFrom: '2026-09-01T00:00:00Z',
        credentialSubject: { id: 'did:example:subject' },
      },
      {
        algorithm: 'URDNA2015',
        format: 'application/n-quads',
        safe: true,
        documentLoader: createDocumentLoader(unusedResolver),
      },
    )

    expect(nquads).toContain('<https://www.w3.org/2018/credentials#VerifiableCredential>')
    expect(nquads).toContain('<https://www.w3.org/2018/credentials#validFrom>')
    expect(nquads).toContain('<https://www.w3.org/2018/credentials#credentialSubject>')
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
