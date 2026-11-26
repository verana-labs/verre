import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2'
import { concatBytes } from '@noble/hashes/utils'
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js'
import { base58, base64urlnopad } from '@scure/base'
import _canonicalize from 'canonicalize'
import { Resolver } from 'did-resolver'
import { describe, expect, it } from 'vitest'

import { IVerreLogger, TrustErrorCode } from '../../src/types'
import { verifySignature } from '../../src/utils/verifier'

const canonicalize = ((_canonicalize as any).default ?? _canonicalize) as (input: unknown) => string

type Document = Parameters<typeof verifySignature>[0]
const silentLogger: IVerreLogger = { debug() {}, info() {}, warn() {}, error() {} }

const resolverFor = (documents: Record<string, unknown>) =>
  ({
    resolve: async (did: string) =>
      documents[did]
        ? { didResolutionMetadata: {}, didDocumentMetadata: {}, didDocument: documents[did] }
        : { didResolutionMetadata: { error: 'notFound' }, didDocumentMetadata: {}, didDocument: null },
  }) as unknown as Resolver
const verify = (document: unknown, resolver: Resolver) =>
  verifySignature(document as Document, resolver, silentLogger)
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value))

// Deterministic keys: a 32-byte ML-DSA-44 seed and an Ed25519 secret key
const mldsaKeys = ml_dsa44.keygen(new Uint8Array(32).fill(7))
const ed25519SecretKey = new Uint8Array(32).fill(9)

// Multikey encodings (Quantum-Resistant Cryptosuites v1.0 §2.1 / Controller Documents)
const MLDSA44_MULTICODEC = new Uint8Array([0x90, 0x24]) // unsigned varint of 0x1210
const ED25519_MULTICODEC = new Uint8Array([0xed, 0x01])
const mldsaMultikey = `u${base64urlnopad.encode(concatBytes(MLDSA44_MULTICODEC, mldsaKeys.publicKey))}`
const ed25519Multikey = `z${base58.encode(
  concatBytes(ED25519_MULTICODEC, ed25519.getPublicKey(ed25519SecretKey)),
)}`

const did = 'did:web:pq.example'
const mldsaVmId = `${did}#mldsa-key`
const ed25519VmId = `${did}#ed25519-key`
const didDocument = {
  '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
  id: did,
  verificationMethod: [
    { id: ed25519VmId, type: 'Multikey', controller: did, publicKeyMultibase: ed25519Multikey },
    { id: mldsaVmId, type: 'Multikey', controller: did, publicKeyMultibase: mldsaMultikey },
  ],
  assertionMethod: [ed25519VmId, mldsaVmId],
  authentication: [ed25519VmId, mldsaVmId],
}
const resolver = resolverFor({ [did]: didDocument })

const unsecuredCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  id: 'https://pq.example/credentials/service',
  type: ['VerifiableCredential'],
  issuer: did,
  validFrom: '2026-11-01T00:00:00Z',
  credentialSubject: { id: did, name: 'PQ service' },
}

const mldsaProofOptions = {
  type: 'DataIntegrityProof',
  cryptosuite: 'mldsa44-jcs-2024',
  verificationMethod: mldsaVmId,
  proofPurpose: 'assertionMethod',
}
const eddsaProofOptions = {
  ...mldsaProofOptions,
  cryptosuite: 'eddsa-jcs-2022',
  verificationMethod: ed25519VmId,
}

/** JCS hash data shared by eddsa-jcs-2022 and mldsa44-jcs-2024 */
const hashData = (unsecured: Record<string, unknown>, proofConfig: Record<string, unknown>) =>
  concatBytes(sha256(canonicalize(proofConfig)), sha256(canonicalize(unsecured)))

const signMldsa = (unsecured: Record<string, unknown>, proofOptions: Record<string, unknown>) => {
  const proofConfig = { ...proofOptions, '@context': unsecured['@context'] }
  const signature = ml_dsa44.sign(hashData(unsecured, proofConfig), mldsaKeys.secretKey)
  return { ...proofConfig, proofValue: `u${base64urlnopad.encode(signature)}` }
}
const signEddsa = (unsecured: Record<string, unknown>, proofOptions: Record<string, unknown>) => {
  const proofConfig = { ...proofOptions, '@context': unsecured['@context'] }
  const signature = ed25519.sign(hashData(unsecured, proofConfig), ed25519SecretKey)
  return { ...proofConfig, proofValue: `z${base58.encode(signature)}` }
}
const secure = (proof: unknown, unsecured: Record<string, unknown> = unsecuredCredential) => ({
  ...unsecured,
  proof,
})
const presentation = (verifiableCredential: unknown[]) => ({
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiablePresentation'],
  holder: did,
  verifiableCredential,
})

describe('DataIntegrityProof (mldsa44-jcs-2024) verification', () => {
  it('uses the FIPS 204 ML-DSA-44 sizes', () => {
    expect(mldsaKeys.publicKey.length).toBe(1312)
    expect(ml_dsa44.sign(new Uint8Array(1), mldsaKeys.secretKey).length).toBe(2420)
  })

  it('verifies a credential signed with ML-DSA-44 whose key is a base64url Multikey', async () => {
    const { result, error } = await verify(
      secure(signMldsa(unsecuredCredential, mldsaProofOptions)),
      resolver,
    )
    expect(error).toBeUndefined()
    expect(result).toBe(true)
  })

  it('verifies a presentation and the credential it carries, both ML-DSA-44', async () => {
    const vc = secure(signMldsa(unsecuredCredential, mldsaProofOptions))
    const unsecuredVp = presentation([vc])
    const vp = secure(
      signMldsa(unsecuredVp, { ...mldsaProofOptions, proofPurpose: 'authentication' }),
      unsecuredVp,
    )
    const { result, error } = await verify(vp, resolver)
    expect(error).toBeUndefined()
    expect(result).toBe(true)
  })

  it('verifies mixed suites: an Ed25519 presentation carrying an ML-DSA-44 credential and vice versa', async () => {
    const mldsaVc = secure(signMldsa(unsecuredCredential, mldsaProofOptions))
    const eddsaVc = secure(signEddsa(unsecuredCredential, eddsaProofOptions))

    const vp1 = presentation([mldsaVc])
    expect((await verify(secure(signEddsa(vp1, eddsaProofOptions), vp1), resolver)).result).toBe(true)

    const vp2 = presentation([eddsaVc])
    expect((await verify(secure(signMldsa(vp2, mldsaProofOptions), vp2), resolver)).result).toBe(true)
  })

  it('rejects an altered document', async () => {
    const vc = clone(secure(signMldsa(unsecuredCredential, mldsaProofOptions))) as Record<string, any>
    vc.credentialSubject.name = 'Someone else'
    const { result, error } = await verify(vc, resolver)
    expect(result).toBe(false)
    expect(error).toBe('ML-DSA-44 signature verification failed')
  })

  it('rejects an altered proofValue', async () => {
    const proof = signMldsa(unsecuredCredential, mldsaProofOptions)
    const signature = base64urlnopad.decode(proof.proofValue.slice(1))
    signature[100] ^= 0xff
    const { result, error } = await verify(
      secure({ ...proof, proofValue: `u${base64urlnopad.encode(signature)}` }),
      resolver,
    )
    expect(result).toBe(false)
    expect(error).toMatch(/^ML-DSA-44 signature verification failed/)
  })

  it('attributes an altered carried credential to itself when the presentation proof holds', async () => {
    const vc = clone(secure(signMldsa(unsecuredCredential, mldsaProofOptions))) as Record<string, any>
    vc.credentialSubject.name = 'Someone else'
    const unsecuredVp = presentation([vc])
    const vp = secure(
      signMldsa(unsecuredVp, { ...mldsaProofOptions, proofPurpose: 'authentication' }),
      unsecuredVp,
    )
    const { result, failedCredentials } = await verify(vp, resolver)
    expect(result).toBe(false)
    expect(failedCredentials).toEqual([
      expect.objectContaining({
        id: unsecuredCredential.id,
        errorCode: TrustErrorCode.VERIFICATION_FAILED,
        error: 'ML-DSA-44 signature verification failed',
      }),
    ])
  })

  it('requires the proofValue to be base64url multibase and 2420 bytes long', async () => {
    const proof = signMldsa(unsecuredCredential, mldsaProofOptions)
    const signature = base64urlnopad.decode(proof.proofValue.slice(1))

    const base58Encoded = await verify(
      secure({ ...proof, proofValue: `z${base58.encode(signature)}` }),
      resolver,
    )
    expect(base58Encoded.error).toBe('Missing or invalid proofValue (expected multibase base64url)')

    const short = await verify(
      secure({ ...proof, proofValue: `u${base64urlnopad.encode(signature.slice(0, 64))}` }),
      resolver,
    )
    expect(short.error).toBe('Invalid ML-DSA-44 signature length: 64')
  })

  it('rejects a proof whose verification method holds a key of another algorithm', async () => {
    const mldsaWithEd25519Key = signMldsa(unsecuredCredential, {
      ...mldsaProofOptions,
      verificationMethod: ed25519VmId,
    })
    expect((await verify(secure(mldsaWithEd25519Key), resolver)).error).toBe(
      `Verification method ${ed25519VmId} holds a Ed25519 key, but the proof requires ML-DSA-44`,
    )

    const eddsaWithMldsaKey = signEddsa(unsecuredCredential, {
      ...eddsaProofOptions,
      verificationMethod: mldsaVmId,
    })
    expect((await verify(secure(eddsaWithMldsaKey), resolver)).error).toBe(
      `Verification method ${mldsaVmId} holds a ML-DSA-44 key, but the proof requires Ed25519`,
    )
  })

  it('accepts the ML-DSA-44 key as an AKP JSON Web Key (RFC 9964)', async () => {
    const jwkResolver = resolverFor({
      [did]: {
        ...didDocument,
        verificationMethod: [
          {
            id: mldsaVmId,
            type: 'JsonWebKey',
            controller: did,
            publicKeyJwk: { kty: 'AKP', alg: 'ML-DSA-44', pub: base64urlnopad.encode(mldsaKeys.publicKey) },
          },
        ],
      },
    })
    const { result, error } = await verify(
      secure(signMldsa(unsecuredCredential, mldsaProofOptions)),
      jwkResolver,
    )
    expect(error).toBeUndefined()
    expect(result).toBe(true)
  })

  it('accepts the ML-DSA-44 Multikey in base58-btc too, keyed on the multicodec header', async () => {
    const base58Resolver = resolverFor({
      [did]: {
        ...didDocument,
        verificationMethod: [
          {
            id: mldsaVmId,
            type: 'Multikey',
            controller: did,
            publicKeyMultibase: `z${base58.encode(concatBytes(MLDSA44_MULTICODEC, mldsaKeys.publicKey))}`,
          },
        ],
      },
    })
    const { result, error } = await verify(
      secure(signMldsa(unsecuredCredential, mldsaProofOptions)),
      base58Resolver,
    )
    expect(error).toBeUndefined()
    expect(result).toBe(true)
  })

  it('rejects an AKP key of another parameter set', async () => {
    const jwkResolver = resolverFor({
      [did]: {
        ...didDocument,
        verificationMethod: [
          {
            id: mldsaVmId,
            type: 'JsonWebKey',
            controller: did,
            publicKeyJwk: { kty: 'AKP', alg: 'ML-DSA-65', pub: base64urlnopad.encode(mldsaKeys.publicKey) },
          },
        ],
      },
    })
    const { result, error } = await verify(
      secure(signMldsa(unsecuredCredential, mldsaProofOptions)),
      jwkResolver,
    )
    expect(result).toBe(false)
    expect(error).toBe(`No supported ML-DSA-44 public key in verification method: ${mldsaVmId}`)
  })

  it('rejects an AKP key that is not 1312 bytes long', async () => {
    const jwkResolver = resolverFor({
      [did]: {
        ...didDocument,
        verificationMethod: [
          {
            id: mldsaVmId,
            type: 'JsonWebKey',
            controller: did,
            // ML-DSA-44 named, ML-DSA-65 sized
            publicKeyJwk: { kty: 'AKP', alg: 'ML-DSA-44', pub: base64urlnopad.encode(new Uint8Array(1952)) },
          },
        ],
      },
    })
    const { result, error } = await verify(
      secure(signMldsa(unsecuredCredential, mldsaProofOptions)),
      jwkResolver,
    )
    expect(result).toBe(false)
    expect(error).toBe(`No supported ML-DSA-44 public key in verification method: ${mldsaVmId}`)
  })

  it('still rejects a cryptosuite it does not know', async () => {
    const proof = { ...signMldsa(unsecuredCredential, mldsaProofOptions), cryptosuite: 'mldsa65-jcs-2024' }
    const { result, error } = await verify(secure(proof), resolver)
    expect(result).toBe(false)
    expect(error).toBe('Unsupported cryptosuite: mldsa65-jcs-2024')
  })
})
