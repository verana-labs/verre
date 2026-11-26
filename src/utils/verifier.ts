import type { W3cJsonLdVerifiableCredential, W3cJsonLdVerifiablePresentation } from '@credo-ts/core'

import jsonld from '@digitalcredentials/jsonld'
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToHex, concatBytes } from '@noble/hashes/utils'
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js'
import { base58, base64urlnopad } from '@scure/base'
import _canonicalize from 'canonicalize'
import { DIDDocument, Resolver, VerificationMethod } from 'did-resolver'

import { createDocumentLoader } from '../libraries/index.js'
import { TrustErrorCode, IVerreLogger, FailedCredential, CREDENTIAL_FORMAT_LDP_VC } from '../types.js'

import { computeDigestSRI, hash } from './crypto.js'
import { TrustError } from './trustError.js'

// Node16 CJS interop: default import may be the namespace or the value itself
const canonicalize = ((_canonicalize as any).default ?? _canonicalize) as (
  input: unknown,
) => string | undefined

// RFC 7515 base64url is unpadded, but legacy signers emit padded values; accept both
const decodeBase64url = (value: string): Uint8Array => base64urlnopad.decode(value.replace(/=+$/u, ''))

/** Signature algorithms a verification method key can belong to. */
type KeyType = 'Ed25519' | 'ML-DSA-44'
type PublicKey = { keyType: KeyType; bytes: Uint8Array }

/** Multibase prefixes in use: base58-btc (`z`) and base64url without padding (`u`). */
type MultibasePrefix = 'z' | 'u'
const MULTIBASE_NAMES: Record<MultibasePrefix, string> = { z: 'base58-btc', u: 'base64url' }

const decodeMultibase = (value: string): { prefix: MultibasePrefix; bytes: Uint8Array } | null => {
  const prefix = value[0]
  if (prefix === 'z') return { prefix, bytes: base58.decode(value.slice(1)) }
  if (prefix === 'u') return { prefix, bytes: base64urlnopad.decode(value.slice(1)) }
  return null
}

// Multikey public keys: unsigned-varint multicodec header followed by the raw key
// (https://github.com/multiformats/multicodec/blob/master/table.csv)
const MULTICODEC_KEYS: { header: number[]; keyType: KeyType; length: number }[] = [
  { header: [0xed, 0x01], keyType: 'Ed25519', length: 32 }, // ed25519-pub, code 0xed
  { header: [0x90, 0x24], keyType: 'ML-DSA-44', length: 1312 }, // ml-dsa-44-pub, code 0x1210
]

// Linked Data Proof suites, verified over the RDF canonicalization of the JSON-LD document
const LINKED_DATA_PROOF_TYPES = ['Ed25519Signature2020', 'Ed25519Signature2018']

const DATA_INTEGRITY_PROOF_TYPE = 'DataIntegrityProof'

/**
 * A JCS Data Integrity cryptosuite: every supported suite transforms the document with JCS and
 * hashes proof config and document with SHA-256; they differ in the signature algorithm, the key it
 * needs, the signature size and the multibase the `proofValue` is encoded with.
 */
interface JcsCryptosuite {
  name: string
  keyType: KeyType
  signatureLength: number
  proofValueMultibase: MultibasePrefix
  verify: (signature: Uint8Array, data: Uint8Array, publicKey: Uint8Array) => boolean
}

// VC Data Integrity proofs are dispatched on their cryptosuite
const DATA_INTEGRITY_CRYPTOSUITES: Record<string, JcsCryptosuite> = {
  // EdDSA Cryptosuites v1.0 §3.3
  'eddsa-jcs-2022': {
    name: 'eddsa-jcs-2022',
    keyType: 'Ed25519',
    signatureLength: 64,
    proofValueMultibase: 'z',
    verify: (signature, data, publicKey) => ed25519.verify(signature, data, publicKey),
  },
  // Quantum-Resistant Cryptosuites v1.0 (FPWD): ML-DSA-44 (FIPS 204) pure signing with an empty context
  'mldsa44-jcs-2024': {
    name: 'mldsa44-jcs-2024',
    keyType: 'ML-DSA-44',
    signatureLength: 2420,
    proofValueMultibase: 'u',
    verify: (signature, data, publicKey) => ml_dsa44.verify(signature, data, publicKey),
  },
}

type ProofPurpose = 'assertionMethod' | 'authentication'
// a credential proof asserts claims; a presentation proof authenticates the holder, but holders
// that sign their linked presentations with the issuance key use assertionMethod too
const CREDENTIAL_PROOF_PURPOSES: ProofPurpose[] = ['assertionMethod']
const PRESENTATION_PROOF_PURPOSES: ProofPurpose[] = ['authentication', 'assertionMethod']

type ProofVerification = { isValid: boolean; error?: string }
const invalid = (error: string): ProofVerification => ({ isValid: false, error })

const asArray = <T>(value: T | T[] | undefined): T[] =>
  value === undefined ? [] : Array.isArray(value) ? value : [value]

const createMessageDigest = () => ({
  _data: '' as string,
  update(msg: string) {
    this._data += msg
  },
  digest() {
    return bytesToHex(hash('SHA256', this._data))
  },
})

/**
 * Recursively verifies the digital proof of a W3C Verifiable Presentation (VP) or Verifiable Credential (VC).
 *
 * This function checks that the input document is a valid VP or VC, verifies its proof using
 * the appropriate Linked Data signature suite or Data Integrity cryptosuite and proof purpose,
 * and—if it's a presentation—recursively verifies the embedded credentials.
 *
 * @param document - A W3C Verifiable Presentation or Verifiable Credential in JSON-LD format.
 * @returns A promise resolving to `{ result: true }` if the proof is valid (including all nested VCs).
 * On failure, `result` is `false` and — when specific embedded credentials were at fault —
 * `failedCredentials` identifies which ones and why.
 */
export async function verifySignature(
  document: W3cJsonLdVerifiablePresentation | W3cJsonLdVerifiableCredential,
  didResolver: Resolver,
  logger: IVerreLogger,
): Promise<{ result: boolean; error?: string; failedCredentials?: FailedCredential[] }> {
  let jsonLdCredentials: W3cJsonLdVerifiableCredential[] = []
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

    let vcPromises: Promise<{
      result: boolean
      error?: string
      failedCredentials?: FailedCredential[]
    }>[] = []
    if (isPresentation && isVerifiablePresentation(document)) {
      logger.debug('Verifying embedded credentials in presentation')
      const credentials = Array.isArray(document.verifiableCredential)
        ? document.verifiableCredential
        : [document.verifiableCredential]
      jsonLdCredentials = credentials.filter((vc): vc is W3cJsonLdVerifiableCredential => 'proof' in vc)
      logger.debug('Processing embedded credentials', { count: jsonLdCredentials.length })
      vcPromises = jsonLdCredentials.map(vc => verifySignature(vc, didResolver, logger))
    }

    const result = await verifyJsonLdCredential(
      document as unknown as Record<string, unknown>,
      isPresentation,
      didResolver,
      logger,
    )
    if (!result.isValid) {
      const error = typeof result.error === 'string' ? result.error : JSON.stringify(result?.error)
      logger.error('Signature verification failed', { error })
      return { result: result.isValid, error }
    }

    logger.debug('Document signature verified successfully')

    if (vcPromises.length > 0) {
      const vcResults = await Promise.all(vcPromises)
      const failedCredentials = vcResults.flatMap<FailedCredential>((r, index) => {
        if (r.result) return []
        const vc = jsonLdCredentials[index]
        return [
          {
            id: typeof vc?.id === 'string' ? vc.id : undefined,
            format: CREDENTIAL_FORMAT_LDP_VC,
            error: r.error ?? 'Signature verification failed',
            errorCode: TrustErrorCode.VERIFICATION_FAILED,
          },
          ...(r.failedCredentials ?? []),
        ]
      })
      if (failedCredentials.length > 0) {
        throw new TrustError(
          TrustErrorCode.VERIFICATION_FAILED,
          'One or more verifiable credentials failed signature verification.',
          failedCredentials,
        )
      }
      logger.debug('All embedded credentials verified successfully')
    }
    return { result: result.isValid }
  } catch (error) {
    logger.error('Signature verification exception', error)
    return {
      result: false,
      error: error.message,
      failedCredentials: error instanceof TrustError ? error.failedCredentials : undefined,
    }
  }
}

/**
 * Verifies every proof carried by a JSON-LD Verifiable Credential or Presentation.
 *
 * `proof` may be a single proof or a proof set; each proof is verified against the document
 * without its `proof` member and all of them must be valid. A proof is dispatched on its type:
 *   - `DataIntegrityProof` (VC Data Integrity 1.0) with the `eddsa-jcs-2022` or `mldsa44-jcs-2024` cryptosuite
 *   - `Ed25519Signature2020` / `Ed25519Signature2018` Linked Data Proofs
 *
 * @param vc              The credential or presentation as a JSON-LD object.
 * @param isPresentation  Whether the document is a presentation, which decides the accepted proof purposes.
 * @param didResolver     Resolver of the verification method controller documents.
 * @param logger          Logger instance used for debug information.
 *
 * @returns               Promise resolving to:
 *                        - { isValid: true } if every proof is valid
 *                        - { isValid: false, error } if verification fails
 */
async function verifyJsonLdCredential(
  vc: Record<string, unknown>,
  isPresentation: boolean,
  didResolver: Resolver,
  logger: IVerreLogger,
): Promise<ProofVerification> {
  const context = vc['@context'] || vc['context']
  if (!context) return invalid('Credential is missing context (@context)')
  if (!vc.proof) return invalid('Credential has no proof')

  const proofs = asArray(vc.proof as Record<string, unknown> | Record<string, unknown>[])
  if (proofs.length === 0) return invalid('Credential has no proof')

  const allowedProofPurposes = isPresentation ? PRESENTATION_PROOF_PURPOSES : CREDENTIAL_PROOF_PURPOSES
  for (const proof of proofs) {
    if (!proof || typeof proof !== 'object') return invalid('Credential proof must be an object')
    const result =
      proof.type === DATA_INTEGRITY_PROOF_TYPE
        ? await verifyDataIntegrityProof(vc, proof, allowedProofPurposes, didResolver, logger)
        : await verifyLinkedDataProof(vc, proof, context, allowedProofPurposes, didResolver, logger)
    if (!result.isValid) return result
  }
  return { isValid: true }
}

/**
 * Verifies a Linked Data Proof of type Ed25519Signature2020 or Ed25519Signature2018.
 *
 * ---------------------------------------------------------------------------
 * Ed25519Signature2020 / Ed25519Signature2018 verification
 * (JSON-LD Linked Data Proofs)
 *
 * Algorithm (W3C LD-Proofs + Ed25519Signature2020 spec):
 *   1. Ensure the proof is of a supported type
 *   2. Separate proof from document
 *   3. Canonicalize proof options (proof without proofValue, with @context)
 *   4. Canonicalize document (without proof)
 *   5. verifyData = SHA-256(proofOptionsNQuads) || SHA-256(documentNQuads)
 *   6. Decode proofValue from multibase base58 ('z' prefix)
 *   7. Resolve the verification method and check it is authorised for `proofPurpose`
 *      in the controller DID document
 *   8. Verify Ed25519 signature over verifyData
 *
 * @param vc                    The Verifiable Credential as a JSON-LD object.
 * @param proof                 The proof under verification.
 * @param context               The document `@context`, which the proof options are canonicalized under.
 * @param allowedProofPurposes  The proof purposes acceptable for this kind of document.
 * @param logger                Logger instance used for debug information.
 */
async function verifyLinkedDataProof(
  vc: Record<string, unknown>,
  proof: Record<string, unknown>,
  context: unknown,
  allowedProofPurposes: ProofPurpose[],
  didResolver: Resolver,
  logger: IVerreLogger,
): Promise<ProofVerification> {
  const proofType = proof.type as string
  if (!LINKED_DATA_PROOF_TYPES.includes(proofType)) {
    return invalid(`Unsupported proof type: ${proofType}`)
  }

  const verificationMethodId = proof.verificationMethod as string | undefined
  if (!verificationMethodId) {
    return invalid('Missing verificationMethod in proof')
  }
  const purpose = checkProofPurpose(proof.proofPurpose, allowedProofPurposes)
  if (typeof purpose !== 'string') return purpose

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
      return invalid('Missing or invalid proofValue (expected multibase base58)')
    }
    signatureBytes = base58.decode(proofValue.slice(1))
    verifyData = concatBytes(proofHash, docHash)
  } else if (proofType === 'Ed25519Signature2018') {
    const { jws } = proof

    if (typeof jws !== 'string' || !jws.includes('..')) {
      return invalid('Invalid or missing JWS detached signature')
    }

    const [header, , signaturePart] = jws.split('.')
    signatureBytes = decodeBase64url(signaturePart)
    verifyData = concatBytes(
      new TextEncoder().encode(`${header}.`),
      proofHash as Uint8Array,
      docHash as Uint8Array,
    )
  } else {
    return invalid(`Unsupported proof type: ${proofType}`)
  }

  const publicKey = await resolveAuthorizedPublicKey(
    verificationMethodId,
    purpose,
    'Ed25519',
    didResolver,
    logger,
  )
  if (!(publicKey instanceof Uint8Array)) return publicKey

  const valid = ed25519.verify(signatureBytes, verifyData, publicKey)
  if (!valid) {
    return invalid('Ed25519 signature verification failed')
  }

  logger.debug(`${proofType} verified OK`, {
    vcId: vc.id,
    verificationMethod: verificationMethodId,
    proofPurpose: purpose,
  })
  return { isValid: true }
}

/**
 * Verifies a `DataIntegrityProof` secured with a supported JCS cryptosuite.
 *
 * ---------------------------------------------------------------------------
 * DataIntegrityProof / eddsa-jcs-2022 and mldsa44-jcs-2024 verification
 * (W3C VC Data Integrity 1.0 §4.4, EdDSA Cryptosuites v1.0 §3.3,
 *  Quantum-Resistant Cryptosuites v1.0 §3.1)
 *
 * Algorithm:
 *   1. Ensure the cryptosuite is supported and the proof carries the required members
 *   2. proofConfig = proof without proofValue; the document is bound to the proof `@context`
 *      when one is present (the document `@context` must start with it)
 *   3. transformedDocument = JCS(document without proof), canonicalProofConfig = JCS(proofConfig)
 *   4. hashData = SHA-256(canonicalProofConfig) || SHA-256(transformedDocument)
 *   5. Decode proofValue from the multibase the suite mandates (base58-btc `z` for EdDSA,
 *      base64url `u` for ML-DSA) into a signature of the suite's length (64 / 2420 bytes)
 *   6. Resolve the verification method, check it is authorised for `proofPurpose` in the
 *      controller DID document and holds a key of the suite's algorithm
 *   7. Verify the signature over hashData (Ed25519, or ML-DSA-44 pure mode with an empty context)
 *
 * The JCS cryptosuites never expand the document as JSON-LD, so no context is fetched.
 *
 * @param document              The credential or presentation as a JSON object.
 * @param proof                 The proof under verification.
 * @param allowedProofPurposes  The proof purposes acceptable for this kind of document.
 */
async function verifyDataIntegrityProof(
  document: Record<string, unknown>,
  proof: Record<string, unknown>,
  allowedProofPurposes: ProofPurpose[],
  didResolver: Resolver,
  logger: IVerreLogger,
): Promise<ProofVerification> {
  const { proofValue, ...proofConfig } = proof

  const suite =
    typeof proofConfig.cryptosuite === 'string'
      ? DATA_INTEGRITY_CRYPTOSUITES[proofConfig.cryptosuite]
      : undefined
  if (!suite) {
    return invalid(`Unsupported cryptosuite: ${String(proofConfig.cryptosuite)}`)
  }
  const verificationMethodId = proofConfig.verificationMethod
  if (typeof verificationMethodId !== 'string') {
    return invalid('Missing verificationMethod in proof')
  }
  const proofPurpose = checkProofPurpose(proofConfig.proofPurpose, allowedProofPurposes)
  if (typeof proofPurpose !== 'string') return proofPurpose
  const multibaseName = MULTIBASE_NAMES[suite.proofValueMultibase]
  if (typeof proofValue !== 'string' || !proofValue.startsWith(suite.proofValueMultibase)) {
    return invalid(`Missing or invalid proofValue (expected multibase ${multibaseName})`)
  }
  let signatureBytes: Uint8Array
  try {
    signatureBytes = decodeMultibase(proofValue)!.bytes
  } catch {
    return invalid(`Invalid proofValue (expected multibase ${multibaseName})`)
  }
  if (signatureBytes.length !== suite.signatureLength) {
    return invalid(`Invalid ${suite.keyType} signature length: ${signatureBytes.length}`)
  }

  const unsecuredDocument: Record<string, unknown> = { ...document }
  delete unsecuredDocument.proof
  if ('@context' in proofConfig) {
    // the proof binds the document to its own @context, which must be a prefix of the document's
    const proofContext = asArray(proofConfig['@context'])
    const documentContext = asArray(unsecuredDocument['@context'])
    const bound =
      documentContext.length >= proofContext.length &&
      proofContext.every((value, index) => canonicalize(documentContext[index]) === canonicalize(value))
    if (!bound) return invalid('The proof @context is not a prefix of the document @context')
    unsecuredDocument['@context'] = proofConfig['@context']
  }

  const transformedDocument = canonicalize(unsecuredDocument)
  const canonicalProofConfig = canonicalize(proofConfig)
  if (!transformedDocument || !canonicalProofConfig) {
    return invalid('Failed to canonicalize the document for verification')
  }
  const verifyData = concatBytes(hash('SHA256', canonicalProofConfig), hash('SHA256', transformedDocument))

  const publicKey = await resolveAuthorizedPublicKey(
    verificationMethodId,
    proofPurpose,
    suite.keyType,
    didResolver,
    logger,
  )
  if (!(publicKey instanceof Uint8Array)) return publicKey

  let valid: boolean
  try {
    valid = suite.verify(signatureBytes, verifyData, publicKey)
  } catch (error) {
    return invalid(
      `${suite.keyType} signature verification failed: ${error instanceof Error ? error.message : error}`,
    )
  }
  if (!valid) {
    return invalid(`${suite.keyType} signature verification failed`)
  }

  logger.debug(`${DATA_INTEGRITY_PROOF_TYPE} (${suite.name}) verified OK`, {
    id: document.id,
    verificationMethod: verificationMethodId,
    proofPurpose,
  })
  return { isValid: true }
}

/**
 * Checks that a proof declares a purpose this kind of document accepts.
 * @returns The proof purpose, or the failed verification.
 */
function checkProofPurpose(
  proofPurpose: unknown,
  allowedProofPurposes: ProofPurpose[],
): ProofPurpose | ProofVerification {
  if (typeof proofPurpose !== 'string') return invalid('Missing proofPurpose in proof')
  if (!allowedProofPurposes.includes(proofPurpose as ProofPurpose)) {
    return invalid(
      `Unexpected proofPurpose '${proofPurpose}', expected one of: ${allowedProofPurposes.join(', ')}`,
    )
  }
  return proofPurpose as ProofPurpose
}

/**
 * Resolves a verification method DID URL to its raw public key, provided the controller DID
 * document authorizes the method for the proof purpose and the key is of the algorithm the
 * proof's suite signs with.
 * @param verificationMethodId Full DID URL of the verification method (e.g. did:example:123#key-1).
 * @param keyType              The key algorithm the suite under verification requires.
 * @returns The public key bytes, or the failed verification.
 */
async function resolveAuthorizedPublicKey(
  verificationMethodId: string,
  proofPurpose: ProofPurpose,
  keyType: KeyType,
  didResolver: Resolver,
  logger: IVerreLogger,
): Promise<Uint8Array | ProofVerification> {
  const resolved = await resolveVerificationMethod(verificationMethodId, didResolver, logger)
  if (!resolved) {
    return invalid(`Cannot resolve verification method: ${verificationMethodId}`)
  }
  if (!isAuthorizedForPurpose(resolved.didDocument, verificationMethodId, proofPurpose)) {
    return invalid(
      `Verification method ${verificationMethodId} is not authorized for proof purpose '${proofPurpose}'`,
    )
  }
  const publicKey = extractPublicKey(resolved.verificationMethod, logger)
  if (!publicKey) {
    return invalid(`No supported ${keyType} public key in verification method: ${verificationMethodId}`)
  }
  if (publicKey.keyType !== keyType) {
    return invalid(
      `Verification method ${verificationMethodId} holds a ${publicKey.keyType} key, but the proof requires ${keyType}`,
    )
  }
  return publicKey.bytes
}

/**
 * Resolves the controller DID document of a verification method and dereferences the method in it.
 *
 * Verification methods are looked up in `verificationMethod` (or the legacy `publicKey`) and,
 * as the DID Core data model allows, embedded directly in a verification relationship.
 * Relative method ids (`#key-1`) are resolved against the document id.
 *
 * @param verificationMethodId Full DID URL of the verification method (e.g. did:example:123#key-1).
 * @returns The DID document and the verification method, or null when either cannot be resolved.
 */
async function resolveVerificationMethod(
  verificationMethodId: string,
  didResolver: Resolver,
  logger: IVerreLogger,
): Promise<{ didDocument: DIDDocument; verificationMethod: VerificationMethod } | null> {
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
  const embedded = [...asArray(didDoc.assertionMethod), ...asArray(didDoc.authentication)].filter(
    (entry): entry is VerificationMethod => typeof entry === 'object' && entry !== null,
  )
  const verificationMethods: VerificationMethod[] = [
    ...(didDoc.verificationMethod ?? didDoc.publicKey ?? []),
    ...embedded,
  ]
  const vm = verificationMethods.find(m => absoluteId(m.id, didDoc.id) === verificationMethodId)
  if (!vm) {
    logger.debug('Verification method not found', {
      verificationMethodId,
      available: verificationMethods.map(m => m.id),
    })
    return null
  }
  return { didDocument: didDoc, verificationMethod: vm }
}

/**
 * Extracts the raw public key and its algorithm from a verification method.
 *
 * Supports:
 *   - `publicKeyMultibase` in base58-btc (`z`) or base64url (`u`), as a Multikey (multicodec header
 *     `0xed01` Ed25519, `0x9024` ML-DSA-44) or as a bare 32-byte Ed25519 key
 *   - `publicKeyBase58` (Ed25519)
 *   - `publicKeyJwk`: OKP/Ed25519 (`x`) or AKP/ML-DSA-44 (`pub`, RFC 9964)
 */
function extractPublicKey(vm: VerificationMethod, logger: IVerreLogger): PublicKey | null {
  const verificationMethodId = vm.id

  if (vm.publicKeyMultibase && typeof vm.publicKeyMultibase === 'string') {
    let decoded: Uint8Array
    try {
      const multibase = decodeMultibase(vm.publicKeyMultibase as string)
      if (!multibase) {
        logger.debug('Unsupported multibase prefix', { verificationMethodId })
        return null
      }
      decoded = multibase.bytes
    } catch {
      logger.debug('Malformed publicKeyMultibase', { verificationMethodId })
      return null
    }
    const codec = MULTICODEC_KEYS.find(
      ({ header, length }) =>
        decoded.length === header.length + length && header.every((byte, index) => decoded[index] === byte),
    )
    if (codec) {
      return { keyType: codec.keyType, bytes: decoded.slice(codec.header.length) }
    }
    // Legacy: a raw 32-byte Ed25519 key without multicodec header
    if (decoded.length === 32) {
      return { keyType: 'Ed25519', bytes: decoded }
    }
    logger.debug('Unexpected public key length', { verificationMethodId, decodedLength: decoded.length })
    return null
  }

  if (vm.publicKeyBase58 && typeof vm.publicKeyBase58 === 'string') {
    return { keyType: 'Ed25519', bytes: base58.decode(vm.publicKeyBase58 as string) }
  }

  if (vm.publicKeyJwk && typeof vm.publicKeyJwk === 'object') {
    const jwk = vm.publicKeyJwk as Record<string, unknown>
    if (jwk.kty === 'AKP') {
      if (jwk.alg !== 'ML-DSA-44' || typeof jwk.pub !== 'string') {
        logger.debug('Unsupported AKP key', { verificationMethodId, alg: jwk.alg })
        return null
      }
      return { keyType: 'ML-DSA-44', bytes: decodeBase64url(jwk.pub) }
    }
    if (jwk.x && typeof jwk.x === 'string' && (jwk.crv === undefined || jwk.crv === 'Ed25519')) {
      return { keyType: 'Ed25519', bytes: decodeBase64url(jwk.x as string) }
    }
  }

  logger.debug('No supported public key format found', { verificationMethodId, vmType: vm.type })
  return null
}

/**
 * Whether a DID document lists a verification method under the verification relationship named
 * by a proof purpose (VC Data Integrity 1.0 §4.4, step 9, and the Linked Data Proofs proof purpose
 * validation: the method MUST be authorized for it).
 */
function isAuthorizedForPurpose(
  didDocument: DIDDocument,
  verificationMethodId: string,
  proofPurpose: string,
): boolean {
  const relationship = (didDocument as unknown as Record<string, unknown>)[proofPurpose]
  if (!Array.isArray(relationship)) return false
  return relationship.some(entry => {
    const id =
      typeof entry === 'string'
        ? entry
        : entry && typeof entry === 'object'
          ? (entry as { id?: unknown }).id
          : undefined
    return typeof id === 'string' && absoluteId(id, didDocument.id) === verificationMethodId
  })
}

/** Resolves a relative DID URL (`#key-1`) against its DID document id. */
function absoluteId(id: string, did: string): string {
  return id.startsWith('#') ? `${did}${id}` : id
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
  const [algorithm] = expectedDigestSRI.split('-')

  logger.debug('Verifying digest SRI', { expectedDigestSRI: `${expectedDigestSRI}` })

  const computedDigestSRI = computeDigestSRI(algorithm, rawContent)
  logger.debug('Computing hash', { computedHash: computedDigestSRI })

  if (computedDigestSRI !== expectedDigestSRI) {
    throw new TrustError(
      TrustErrorCode.VERIFICATION_FAILED,
      `digestSRI verification failed for ${rawContent}. Computed: ${computedDigestSRI}, Expected: ${expectedDigestSRI}`,
    )
  }

  logger.debug('Digest SRI verified successfully')
}
