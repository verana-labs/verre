import type { W3cJsonLdVerifiableCredential, W3cJsonLdVerifiablePresentation } from '@credo-ts/core'

import jsonld from '@digitalcredentials/jsonld'
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToHex, concatBytes } from '@noble/hashes/utils'
import { base58, base64, base64url } from '@scure/base'
import { Resolver, VerificationMethod } from 'did-resolver'

import { createDocumentLoader } from '../libraries'
import { TrustErrorCode, IVerreLogger } from '../types'

import { hash } from './crypto'
import { TrustError } from './trustError'

// Ed25519 multicodec prefix: 0xed01
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01])

const createMessageDigest = () => ({
  _data: '' as string,
  update(msg: string) { this._data += msg },
  digest() { return bytesToHex(hash('SHA256', this._data)) },
})

/**
 * Recursively verifies the digital proof of a W3C Verifiable Presentation (VP) or Verifiable Credential (VC).
 *
 * This function checks that the input document is a valid VP or VC, verifies its proof using
 * the appropriate Linked Data signature suite and proof purpose, and—if it's a presentation—
 * recursively verifies the embedded credentials.
 *
 * @param document - A W3C Verifiable Presentation or Verifiable Credential in JSON-LD format.
 * @returns A promise that resolves to `true` if the proof is valid (including all nested VCs), or `false` otherwise.
 *
 * @throws Error if the document is not a valid VP or VC, or if any embedded credential fails validation.
 */
export async function verifySignature(
  document: W3cJsonLdVerifiablePresentation | W3cJsonLdVerifiableCredential,
  didResolver: Resolver,
  logger: IVerreLogger,
): Promise<{ result: boolean; error?: string }> {
  try {
    if (
      !document.proof ||
      !(document.type.includes('VerifiablePresentation') || document.type.includes('VerifiableCredential'))
    ) {
      throw new Error(
        'The document must be a Verifiable Presentation, Verifiable Credential with a valid proof must be added.',
      )
    }
    const isPresentation = document.type.includes('VerifiablePresentation')

    const result = await verifyJsonLdCredential(
      document as unknown as Record<string, unknown>,
      didResolver,
      logger,
    )
    if (!result.isValid) {
      const error = JSON.stringify(result?.error)
      logger.error('Signature verification failed', { error })
      return { result: result.isValid, error }
    }

    logger.debug('Document signature verified successfully')

    if (isPresentation && isVerifiablePresentation(document)) {
      logger.debug('Verifying embedded credentials in presentation')
      const credentials = Array.isArray(document.verifiableCredential)
        ? document.verifiableCredential
        : [document.verifiableCredential]

      const jsonLdCredentials = credentials.filter((vc): vc is W3cJsonLdVerifiableCredential => 'proof' in vc)
      logger.debug('Processing embedded credentials', { count: jsonLdCredentials.length })
      const results = await Promise.all(jsonLdCredentials.map(vc => verifySignature(vc, didResolver, logger)))

      const allCredentialsVerified = results.every(verified => verified)
      if (!allCredentialsVerified) {
        throw new Error('One or more verifiable credentials failed signature verification.')
      }
      logger.debug('All embedded credentials verified successfully')
    }
    return { result: result.isValid }
  } catch (error) {
    logger.error('Signature verification exception', error)
    return { result: false, error: error.message }
  }
}

/**
 * Verifies a JSON-LD Verifiable Credential signed using
 * Ed25519Signature2020 or Ed25519Signature2018.
 *
 * ---------------------------------------------------------------------------
 * Ed25519Signature2020 / Ed25519Signature2018 verification
 * (JSON-LD Data Integrity / Linked Data Proofs)
 *
 * Algorithm (W3C LD-Proofs + Ed25519Signature2020 spec):
 *   1. Ensure proof exists and is of a supported type
 *   2. Separate proof from document
 *   3. Canonicalize proof options (proof without proofValue, with @context)
 *   4. Canonicalize document (without proof)
 *   5. verifyData = SHA-256(proofOptionsNQuads) || SHA-256(documentNQuads)
 *   6. Decode proofValue from multibase base58 ('z' prefix)
 *   7. Resolve verification method DID → extract public key
 *   8. Verify Ed25519 signature over verifyData
 *
 * @param vc      The Verifiable Credential as a JSON-LD object.
 * @param logger  Logger instance used for debug information.
 *
 * @returns       Promise resolving to:
 *                - { result: true } if signature is valid
 *                - { result: false, error } if verification fails
 */
async function verifyJsonLdCredential(
  vc: Record<string, unknown>,
  didResolver: Resolver,
  logger: IVerreLogger,
): Promise<{ isValid: boolean; error?: string }> {
  const supportedProofTypes = ['Ed25519Signature2020', 'Ed25519Signature2018']
  const proof = vc.proof as Record<string, unknown> | undefined
  const context = vc['@context'] || vc['context']
  if (!context) return { isValid: false, error: 'Credential is missing context (@context)' }
  if (!proof) return { isValid: false, error: 'Credential has no proof' }

  const proofType = proof.type as string
  if (!supportedProofTypes.includes(proofType)) {
    return { isValid: false, error: `Unsupported proof type: ${proofType}` }
  }

  const verificationMethodId = proof.verificationMethod as string | undefined
  if (!verificationMethodId) {
    return { isValid: false, error: 'Missing verificationMethod in proof' }
  }

  const proofOptions: Record<string, unknown> = { ...proof }
  delete proofOptions.proofValue
  delete proofOptions.jws
  proofOptions['@context'] = context

  const document: Record<string, unknown> = { ...vc }
  delete document.proof

  const documentLoader = createDocumentLoader(didResolver)
  const canonizeOpts = {
    algorithm: 'URDNA2015' as const,
    format: 'application/n-quads' as const,
    safe: false,
    documentLoader,
    createMessageDigest,
  }
  const [proofNQuads, docNQuads] = await Promise.all([
    jsonld.canonize(proofOptions, canonizeOpts),
    jsonld.canonize(document, canonizeOpts),
  ])

  const proofHash = hash('SHA256', proofNQuads as string)
  const docHash = hash('SHA256', docNQuads as string)

  let signatureBytes: Uint8Array
  let verifyData: Uint8Array

  if (proofType === 'Ed25519Signature2020') {
    const proofValue = proof.proofValue as string | undefined
    if (!proofValue || typeof proofValue !== 'string' || !proofValue.startsWith('z')) {
      return { isValid: false, error: 'Missing or invalid proofValue (expected multibase base58)' }
    }
    signatureBytes = base58.decode(proofValue.slice(1))
    verifyData = concatBytes(proofHash, docHash)
  } else if (proofType === 'Ed25519Signature2018') {
    const { jws } = proof

    if (typeof jws !== 'string' || !jws.includes('..')) {
      return { isValid: false, error: 'Invalid or missing JWS detached signature' }
    }

    const [header, , signaturePart] = jws.split('.')
    signatureBytes = base64url.decode(signaturePart)
    verifyData = concatBytes(new TextEncoder().encode(`${header}.`), proofHash as Uint8Array, docHash as Uint8Array)
  } else {
    return { isValid: false, error: `Unsupported proof type: ${proofType}` }
  }

  const publicKeyBytes = await resolvePublicKey(verificationMethodId, didResolver, logger)
  if (!publicKeyBytes) {
    return { isValid: false, error: `Cannot resolve verification method: ${verificationMethodId}` }
  }

  const valid = ed25519.verify(signatureBytes, verifyData, publicKeyBytes)
  if (!valid) {
    return { isValid: false, error: 'Ed25519 signature verification failed' }
  }

  logger.debug(`${proofType} verified OK`, { vcId: vc.id, verificationMethod: verificationMethodId })
  return { isValid: true }
}

/**
 * Resolve a verification method DID URL to a raw Ed25519 public key (32 bytes)
 * @param verificationMethodId Full DID URL of the verification method * (e.g. did:example:123#key-1).
 * @returns
 */
async function resolvePublicKey(
  verificationMethodId: string,
  didResolver: Resolver,
  logger: IVerreLogger,
): Promise<Uint8Array | null> {
  const did = verificationMethodId.split('#')[0]
  const resolution = await didResolver.resolve(did)
  if (resolution.didResolutionMetadata?.error || !resolution.didDocument) {
    logger.debug('Failed to resolve DID for verification method', {
      did,
      error: resolution.didResolutionMetadata?.error,
    })
    return null
  }

  const didDoc = resolution.didDocument

  const verificationMethods: VerificationMethod[] = didDoc.verificationMethod ?? didDoc.publicKey ?? []
  const vm = verificationMethods.find(m => m.id === verificationMethodId)
  if (!vm) {
    logger.debug('Verification method not found', {
      verificationMethodId,
      available: verificationMethods.map(m => m.id),
    })
    return null
  }

  if (vm.publicKeyMultibase && typeof vm.publicKeyMultibase === 'string') {
    const multibase = vm.publicKeyMultibase as string
    if (!multibase.startsWith('z')) {
      logger.debug('Unsupported multibase prefix', { verificationMethodId })
      return null
    }
    const decoded = base58.decode(multibase.slice(1))
    // Strip multicodec prefix if present (0xed 0x01 for Ed25519)
    if (
      decoded.length === 34 &&
      decoded[0] === ED25519_MULTICODEC_PREFIX[0] &&
      decoded[1] === ED25519_MULTICODEC_PREFIX[1]
    ) {
      return decoded.slice(2)
    }
    // Already raw 32-byte key
    if (decoded.length === 32) {
      return decoded
    }
    logger.debug('Unexpected public key length', { verificationMethodId, decodedLength: decoded.length })
    return null
  }

  if (vm.publicKeyBase58 && typeof vm.publicKeyBase58 === 'string') {
    return base58.decode(vm.publicKeyBase58 as string)
  }

  if (vm.publicKeyJwk && typeof vm.publicKeyJwk === 'object') {
    const jwk = vm.publicKeyJwk as Record<string, unknown>
    if (jwk.x && typeof jwk.x === 'string') {
      return base64url.decode(jwk.x as string)
    }
  }

  logger.debug('No supported public key format found', { verificationMethodId, vmType: vm.type })
  return null
}

/**
 * Type guard to determine whether a given document is a Verifiable Presentation.
 *
 * @param doc - The document to evaluate, which may be a VP or VC.
 * @returns `true` if the document is a Verifiable Presentation; otherwise, `false`.
 */
function isVerifiablePresentation(
  doc: W3cJsonLdVerifiablePresentation | W3cJsonLdVerifiableCredential,
): doc is W3cJsonLdVerifiablePresentation {
  const type = Array.isArray(doc.type) ? doc.type : [doc.type]
  return type.includes('VerifiablePresentation')
}

/**
 * Verifies the integrity of a given raw content string using a Subresource Integrity (SRI) digest.
 *
 * The digest is computed over the raw bytes of the content as provided, without any
 * transformation or canonicalization. This aligns with the SRI specification, which
 * requires byte-level integrity verification.
 *
 * @param {string} rawContent - The raw content string to be verified (e.g. as fetched from a URL).
 * @param {string} expectedDigestSRI - The expected SRI digest in the format `{algorithm}-{hash}`.
 * @throws {TrustError} Throws an error if the computed hash does not match the expected hash.
 */
export function verifyDigestSRI(rawContent: string, expectedDigestSRI: string, logger: IVerreLogger) {
  const [algorithm, expectedHash] = expectedDigestSRI.split('-')

  logger.debug('Verifying digest SRI', { expectedDigestSRI: `${expectedDigestSRI}` })

  const computedHash = base64.encode(hash(algorithm, rawContent))
  logger.debug('Computing hash', { computedHash: `${algorithm}-${computedHash}` })

  if (computedHash !== expectedHash) {
    throw new TrustError(
      TrustErrorCode.VERIFICATION_FAILED,
      `digestSRI verification failed for ${rawContent}. Computed: ${computedHash}, Expected: ${expectedHash}`,
    )
  }

  logger.debug('Digest SRI verified successfully')
}
