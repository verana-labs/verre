import { describe, expect, it } from 'vitest'

import { TrustErrorCode } from '../../src/types'
import { computeCredentialDigestJCS } from '../../src/utils/credentialDigest'

const credential = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  id: 'urn:uuid:vtc-1',
  type: ['VerifiableCredential', 'VerifiableTrustCredential'],
  issuer: 'did:webvh:example',
  issuanceDate: '2026-01-01T00:00:00Z',
  credentialSubject: { id: 'did:example:subject', name: 'Acme' },
} as never

const signed = {
  ...(credential as object),
  proof: { type: 'DataIntegrityProof', proofValue: 'zSIG' },
} as never

describe('computeCredentialDigestJCS', () => {
  it('covers the proof, so a signed credential digests differently from the unsigned one', () => {
    expect(computeCredentialDigestJCS(signed, 'sha384')).not.toBe(
      computeCredentialDigestJCS(credential, 'sha384'),
    )
  })

  it('derives the prefix from the schema digest_algorithm', () => {
    expect(computeCredentialDigestJCS(signed, 'sha384')).toMatch(/^sha384-/)
    expect(computeCredentialDigestJCS(signed, 'sha512')).toMatch(/^sha512-/)
  })

  it('rejects an algorithm the spec does not allow', () => {
    expect(() => computeCredentialDigestJCS(signed, 'sha256')).toThrowError(
      expect.objectContaining({
        metadata: expect.objectContaining({ errorCode: TrustErrorCode.NOT_SUPPORTED }),
      }),
    )
  })
})
