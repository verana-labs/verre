import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2'
import { concatBytes } from '@noble/hashes/utils'
import { base58 } from '@scure/base'
import _canonicalize from 'canonicalize'

const canonicalize = ((_canonicalize as any).default ?? _canonicalize) as (input: unknown) => string

// A test Ecosystem that issues JSON Schema Credentials with a real eddsa-jcs-2022 proof, for the
// resolutions that verify signatures for real ([TR-3]). The key is fixed so fixtures are stable.
export const ecosystemDid = 'did:web:ecosystem.example'
export const ecosystemVerificationMethodId = `${ecosystemDid}#key-1`
const ecosystemSecretKey = new Uint8Array(32).fill(0x42)

export const ecosystemDidDocument = {
  '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
  id: ecosystemDid,
  verificationMethod: [
    {
      id: ecosystemVerificationMethodId,
      type: 'Multikey',
      controller: ecosystemDid,
      publicKeyMultibase: `z${base58.encode(
        concatBytes(new Uint8Array([0xed, 0x01]), ed25519.getPublicKey(ecosystemSecretKey)),
      )}`,
    },
  ],
  assertionMethod: [ecosystemVerificationMethodId],
  authentication: [ecosystemVerificationMethodId],
}

export const ecosystemResolver = {
  didResolutionMetadata: {},
  didDocumentMetadata: {},
  didDocument: ecosystemDidDocument,
}

/**
 * Re-issues a schema credential fixture as the test Ecosystem: same content, `issuer` set to the
 * Ecosystem DID and a valid `eddsa-jcs-2022` DataIntegrityProof in place of the placeholder proof.
 */
export const signSchemaCredential = <T extends Record<string, unknown>>(credential: T): T => {
  const { proof: _placeholder, ...rest } = credential
  const unsecured = { ...rest, issuer: ecosystemDid }
  const proofConfig = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: '2024-01-01T00:00:00Z',
    verificationMethod: ecosystemVerificationMethodId,
    proofPurpose: 'assertionMethod',
    '@context': unsecured['@context'],
  }
  const hashData = concatBytes(sha256(canonicalize(proofConfig)), sha256(canonicalize(unsecured)))
  const proofValue = `z${base58.encode(ed25519.sign(hashData, ecosystemSecretKey))}`
  return { ...unsecured, proof: { ...proofConfig, proofValue } } as unknown as T
}
