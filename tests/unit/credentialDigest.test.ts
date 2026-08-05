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

  it('is the encoded digest alone, with no algorithm prefix', () => {
    expect(computeCredentialDigestJCS(signed, 'sha384')).toMatch(/^[A-Za-z0-9+/]+=*$/)
  })

  it('takes the algorithm from the schema, not from the value', () => {
    const sha384 = computeCredentialDigestJCS(signed, 'sha384')
    const sha512 = computeCredentialDigestJCS(signed, 'sha512')
    expect(sha384).not.toBe(sha512)
    expect(Buffer.from(sha384, 'base64')).toHaveLength(48)
    expect(Buffer.from(sha512, 'base64')).toHaveLength(64)
  })

  it('rejects an algorithm the spec does not allow', () => {
    expect(() => computeCredentialDigestJCS(signed, 'sha256')).toThrowError(
      expect.objectContaining({
        metadata: expect.objectContaining({ errorCode: TrustErrorCode.NOT_SUPPORTED }),
      }),
    )
  })
})
