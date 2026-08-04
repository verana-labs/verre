import { createHash } from 'node:crypto'
import { describe, it, expect } from 'vitest'

import { computeCredentialDigestJCS } from '../../src'

function issuerCanonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(issuerCanonicalJson).join(',')}]`
  const obj = value as Record<string, unknown>
  return `{${Object.keys(obj)
    .sort()
    .map(k => `${JSON.stringify(k)}:${issuerCanonicalJson(obj[k])}`)
    .join(',')}}`
}
function anchorDigest(credential: Record<string, unknown>, algo = 'sha384'): string {
  const { proof, ...content } = credential
  void proof
  return `${algo}-${createHash(algo).update(issuerCanonicalJson(content)).digest('base64')}`
}

const credential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  id: 'https://issuer.example/credentials/1',
  type: ['VerifiableCredential', 'VerifiableTrustCredential'],
  issuer: 'did:web:issuer.example',
  validFrom: '2025-01-01T00:00:00Z',
  credentialSubject: { id: 'did:web:subject.example', name: 'Demo Service', minimumAgeRequired: 18 },
  credentialSchema: { id: 'vpr:verana:mainnet/cs/v1/js/1', type: 'JsonSchema' },
  proof: { type: 'DataIntegrityProof', proofValue: 'zSignatureBytes' },
}

describe('computeCredentialDigestJCS', () => {
  it('matches the issuer on-chain anchor recipe byte-for-byte', () => {
    expect(computeCredentialDigestJCS(credential)).toBe(anchorDigest(credential))
  })

  it('defaults to the ECS sha384 algorithm', () => {
    expect(computeCredentialDigestJCS(credential)).toMatch(/^sha384-/)
  })

  it('is unaffected by the proof, since the digest is over pre-signature content', () => {
    const reSigned = { ...credential, proof: { type: 'DataIntegrityProof', proofValue: 'zDifferentBytes' } }
    expect(computeCredentialDigestJCS(reSigned)).toBe(computeCredentialDigestJCS(credential))
  })

  it('keeps the credential id (changing it changes the digest)', () => {
    const otherId = { ...credential, id: 'https://issuer.example/credentials/2' }
    expect(computeCredentialDigestJCS(otherId)).not.toBe(computeCredentialDigestJCS(credential))
  })

  it('honours an explicit digest algorithm', () => {
    expect(computeCredentialDigestJCS(credential, 'sha256')).toBe(anchorDigest(credential, 'sha256'))
  })
})
