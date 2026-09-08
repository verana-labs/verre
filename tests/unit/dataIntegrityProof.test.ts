import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2'
import { concatBytes, randomBytes } from '@noble/hashes/utils'
import { base58 } from '@scure/base'
import _canonicalize from 'canonicalize'
import { Resolver } from 'did-resolver'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { IVerreLogger, TrustErrorCode } from '../../src/types'
import { verifySignature } from '../../src/utils/verifier'
import {
  integrationDidDoc,
  linkedVpService,
  vcdm2Did,
  vcdm2DidDocument,
  vcdm2OrgVp,
  vcdm2ServiceVp,
  vcdm2VerificationMethodId,
} from '../__mocks__'

const canonicalize = ((_canonicalize as any).default ?? _canonicalize) as (input: unknown) => string

type Document = Parameters<typeof verifySignature>[0]
const silentLogger: IVerreLogger = { debug() {}, info() {}, warn() {}, error() {} }
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value))

const resolverFor = (documents: Record<string, unknown>) =>
  ({
    resolve: async (did: string) =>
      documents[did]
        ? { didResolutionMetadata: {}, didDocumentMetadata: {}, didDocument: documents[did] }
        : { didResolutionMetadata: { error: 'notFound' }, didDocumentMetadata: {}, didDocument: null },
  }) as unknown as Resolver

const fixtureResolver = resolverFor({ [vcdm2Did]: vcdm2DidDocument })
const verify = (document: unknown, resolver: Resolver = fixtureResolver) =>
  verifySignature(document as Document, resolver, silentLogger)

// A minimal eddsa-jcs-2022 signer (VC Data Integrity EdDSA Cryptosuites §3.3) for the variants the
// credo-signed fixtures cannot express. Its output is trusted because the same verifier accepts the
// credo fixtures above.
const signerDid = 'did:web:signer.example'
const signerVmId = `${signerDid}#key-1`
const secretKey = randomBytes(32)
const signerDidDocument = {
  '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
  id: signerDid,
  verificationMethod: [
    {
      id: signerVmId,
      type: 'Multikey',
      controller: signerDid,
      publicKeyMultibase: `z${base58.encode(
        concatBytes(new Uint8Array([0xed, 0x01]), ed25519.getPublicKey(secretKey)),
      )}`,
    },
  ],
  // relative and absolute DID URLs are both valid relationship references
  assertionMethod: ['#key-1'],
  authentication: [signerVmId],
}
const signerResolver = resolverFor({ [signerDid]: signerDidDocument })

const baseProof = {
  type: 'DataIntegrityProof',
  cryptosuite: 'eddsa-jcs-2022',
  verificationMethod: signerVmId,
  proofPurpose: 'assertionMethod',
}
const unsecuredCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  id: 'https://signer.example/credentials/1',
  type: ['VerifiableCredential'],
  issuer: signerDid,
  validFrom: '2026-09-01T00:00:00Z',
  credentialSubject: { id: 'did:example:subject' },
}

const signJcs = (unsecured: Record<string, unknown>, proofOptions: Record<string, unknown>) => {
  const proofConfig = { ...proofOptions, '@context': unsecured['@context'] }
  const hashData = concatBytes(sha256(canonicalize(proofConfig)), sha256(canonicalize(unsecured)))
  return { ...proofConfig, proofValue: `z${base58.encode(ed25519.sign(hashData, secretKey))}` }
}
const secure = (proof: unknown, unsecured: Record<string, unknown> = unsecuredCredential) => ({
  ...unsecured,
  proof,
})
/** A presentation by the test signer carrying the given credentials */
const present = (verifiableCredential: unknown[]) => {
  const unsecured = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiablePresentation'],
    holder: signerDid,
    verifiableCredential,
  }
  return secure(signJcs(unsecured, { ...baseProof, proofPurpose: 'authentication' }), unsecured)
}

describe('DataIntegrityProof (eddsa-jcs-2022) verification', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('credo-signed VC Data Model 2.0 linked presentations', () => {
    it.each([
      ['service', vcdm2ServiceVp],
      ['org', vcdm2OrgVp],
    ])('verifies the %s presentation and the credential it carries', async (_name, vp) => {
      const { result, error } = await verify(vp)
      expect(error).toBeUndefined()
      expect(result).toBe(true)
    })

    it('verifies the credential on its own', async () => {
      const { result, error } = await verify(vcdm2ServiceVp.verifiableCredential[0])
      expect(error).toBeUndefined()
      expect(result).toBe(true)
    })

    it('never retrieves a context: the JCS suites canonicalize the plain JSON', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch')
      const { result } = await verify(vcdm2ServiceVp)
      expect(result).toBe(true)
      expect(fetchSpy).not.toHaveBeenCalled()
    })

    it('rejects a presentation whose carried credential was altered, as its own proof covers it', async () => {
      const vp = clone(vcdm2ServiceVp)
      vp.verifiableCredential[0].credentialSubject.name = 'Someone else'
      const { result, error, failedCredentials } = await verify(vp)
      expect(result).toBe(false)
      expect(error).toBe('Ed25519 signature verification failed')
      expect(failedCredentials).toBeUndefined()
    })

    it('attributes an altered credential to itself when the presentation proof holds', async () => {
      const credential = clone(vcdm2ServiceVp.verifiableCredential[0])
      credential.credentialSubject.name = 'Someone else'
      const resolver = resolverFor({ [signerDid]: signerDidDocument, [vcdm2Did]: vcdm2DidDocument })
      const { result, error, failedCredentials } = await verify(present([credential]), resolver)
      expect(result).toBe(false)
      expect(error).toBe('One or more verifiable credentials failed signature verification.')
      expect(failedCredentials).toEqual([
        expect.objectContaining({
          id: credential.id,
          errorCode: TrustErrorCode.VERIFICATION_FAILED,
          error: 'Ed25519 signature verification failed',
        }),
      ])
    })

    it('rejects a presentation whose proofValue was altered', async () => {
      const vp = clone(vcdm2ServiceVp)
      const signature = base58.decode(vp.proof.proofValue.slice(1))
      signature[10] ^= 0xff
      vp.proof.proofValue = `z${base58.encode(signature)}`
      const { result, error } = await verify(vp)
      expect(result).toBe(false)
      expect(error).toMatch(/^Ed25519 signature verification failed/)
    })

    it('rejects an unsupported cryptosuite', async () => {
      const vp = clone(vcdm2ServiceVp)
      vp.proof.cryptosuite = 'ecdsa-jcs-2019'
      const { result, error } = await verify(vp)
      expect(result).toBe(false)
      expect(error).toBe('Unsupported cryptosuite: ecdsa-jcs-2019')
    })

    it('rejects a document whose @context no longer starts with the proof @context', async () => {
      const credential = clone(vcdm2ServiceVp.verifiableCredential[0])
      credential['@context'] = ['https://www.w3.org/ns/credentials/v2']
      const { result, error } = await verify(credential)
      expect(result).toBe(false)
      expect(error).toBe('The proof @context is not a prefix of the document @context')
    })

    it('requires the presentation key to be listed for authentication', async () => {
      const resolver = resolverFor({ [vcdm2Did]: { ...vcdm2DidDocument, authentication: [] } })
      const { result, error } = await verify(vcdm2ServiceVp, resolver)
      expect(result).toBe(false)
      expect(error).toBe(
        `Verification method ${vcdm2VerificationMethodId} is not authorized for proof purpose 'authentication'`,
      )
    })

    it('requires the credential key to be listed for assertionMethod', async () => {
      const resolver = resolverFor({ [vcdm2Did]: { ...vcdm2DidDocument, assertionMethod: [] } })
      const { result, failedCredentials } = await verify(vcdm2ServiceVp, resolver)
      expect(result).toBe(false)
      expect(failedCredentials?.[0]?.error).toBe(
        `Verification method ${vcdm2VerificationMethodId} is not authorized for proof purpose 'assertionMethod'`,
      )
    })

    it('fails when the controller DID cannot be resolved', async () => {
      const { result, error } = await verify(vcdm2ServiceVp, resolverFor({}))
      expect(result).toBe(false)
      expect(error).toBe(`Cannot resolve verification method: ${vcdm2VerificationMethodId}`)
    })
  })

  describe('proof purposes, proof sets and malformed proofs', () => {
    it('accepts a credential proof for assertionMethod referenced relatively in the DID document', async () => {
      const { result, error } = await verify(secure(signJcs(unsecuredCredential, baseProof)), signerResolver)
      expect(error).toBeUndefined()
      expect(result).toBe(true)
    })

    it('rejects a credential proof made for authentication', async () => {
      const proof = signJcs(unsecuredCredential, { ...baseProof, proofPurpose: 'authentication' })
      const { result, error } = await verify(secure(proof), signerResolver)
      expect(result).toBe(false)
      expect(error).toBe("Unexpected proofPurpose 'authentication', expected one of: assertionMethod")
    })

    it('accepts a presentation proof made for assertionMethod', async () => {
      const unsecuredPresentation = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiablePresentation'],
        holder: signerDid,
        verifiableCredential: [secure(signJcs(unsecuredCredential, baseProof))],
      }
      const vp = secure(signJcs(unsecuredPresentation, baseProof), unsecuredPresentation)
      const { result, error } = await verify(vp, signerResolver)
      expect(error).toBeUndefined()
      expect(result).toBe(true)
    })

    it('verifies every proof of a proof set', async () => {
      const proofs = [
        signJcs(unsecuredCredential, { ...baseProof, created: '2026-09-01T00:00:00Z' }),
        signJcs(unsecuredCredential, { ...baseProof, created: '2026-09-02T00:00:00Z' }),
      ]
      expect((await verify(secure(proofs), signerResolver)).result).toBe(true)

      const tampered = [proofs[0], { ...proofs[1], created: '2026-09-03T00:00:00Z' }]
      const { result, error } = await verify(secure(tampered), signerResolver)
      expect(result).toBe(false)
      expect(error).toMatch(/^Ed25519 signature verification failed/)
    })

    it('rejects proof values that are not base58-btc multibase or not 64 bytes long', async () => {
      const proof = signJcs(unsecuredCredential, baseProof)
      const notMultibase = await verify(
        secure({ ...proof, proofValue: `u${proof.proofValue.slice(1)}` }),
        signerResolver,
      )
      expect(notMultibase.error).toBe('Missing or invalid proofValue (expected multibase base58-btc)')

      const short = await verify(
        secure({ ...proof, proofValue: `z${base58.encode(new Uint8Array([1, 2, 3]))}` }),
        signerResolver,
      )
      expect(short.error).toBe('Invalid Ed25519 signature length: 3')
    })

    it('rejects a proof without a proofPurpose or verificationMethod', async () => {
      const proof = signJcs(unsecuredCredential, baseProof)
      const { proofPurpose, ...withoutPurpose } = proof
      expect(proofPurpose).toBe('assertionMethod')
      expect((await verify(secure(withoutPurpose), signerResolver)).error).toBe(
        'Missing proofPurpose in proof',
      )
      const { verificationMethod, ...withoutMethod } = proof
      expect(verificationMethod).toBe(signerVmId)
      expect((await verify(secure(withoutMethod), signerResolver)).error).toBe(
        'Missing verificationMethod in proof',
      )
    })

    it('verifies a Data Integrity presentation carrying a legacy Ed25519Signature2018 credential', async () => {
      const legacyCredential = linkedVpService.verifiableCredential[0]
      const legacyDid = legacyCredential.proof.verificationMethod.split('#')[0]
      const resolver = resolverFor({ [signerDid]: signerDidDocument, [legacyDid]: integrationDidDoc })
      const { result, error } = await verify(present([legacyCredential]), resolver)
      expect(error).toBeUndefined()
      expect(result).toBe(true)
    })
  })
})
