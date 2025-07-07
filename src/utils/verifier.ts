import {
  AgentContext,
  asArray,
  Ed25519Signature2018,
  Ed25519Signature2020,
  JsonTransformer,
  VERIFICATION_METHOD_TYPE_ED25519_VERIFICATION_KEY_2018,
  VERIFICATION_METHOD_TYPE_ED25519_VERIFICATION_KEY_2020,
  W3cJsonLdVerifiableCredential,
  W3cJsonLdVerifiablePresentation,
  W3cJsonLdVerifyCredentialOptions,
  W3cJsonLdVerifyPresentationOptions,
  W3cVerifyCredentialResult,
  W3cVerifyPresentationResult,
} from '@credo-ts/core'
import { Buffer } from 'buffer/'

import {
  assertOnlyW3cJsonLdVerifiableCredentials,
  Ed25519PublicJwk,
  purposes,
  SignatureSuiteRegistry,
} from '../libraries'
import { DEFAULT_CONTEXTS } from '../libraries/contexts'
import vc from '../libraries/vc'
import { TrustErrorCode, W3cJsonCredential } from '../types'

import { hash } from './crypto'
import { TrustError } from './trustError'
import { createKmsKeyPairClass } from '../libraries/KmsKeyPair'

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
  agentContext: AgentContext,
): Promise<boolean> {
  try {
    if (
      !document.proof ||
      !(document.type.includes('VerifiablePresentation') || document.type.includes('VerifiableCredential')) ||
      !agentContext
    ) {
      throw new Error(
        'The document must be a Verifiable Presentation, Verifiable Credential with a valid proof and the agentContext must be added.',
      )
    }
    const isPresentation = document.type.includes('VerifiablePresentation')

    const result = isPresentation
      ? await verifyPresentation({
          presentation: JsonTransformer.fromJSON(document, W3cJsonLdVerifiablePresentation),
          challenge: 'challenge',
          domain: 'example.com',
        })
      : await verifyCredential({
          credential: JsonTransformer.fromJSON(document, W3cJsonLdVerifiableCredential),
          proofPurpose: new purposes.AssertionProofPurpose(),
        })
    if (!result.isValid) return false

    if (isPresentation && isVerifiablePresentation(document)) {
      const credentials = Array.isArray(document.verifiableCredential)
        ? document.verifiableCredential
        : [document.verifiableCredential]

      const jsonLdCredentials = credentials.filter((vc): vc is W3cJsonLdVerifiableCredential => 'proof' in vc)
      const results = await Promise.all(jsonLdCredentials.map(vc => verifySignature(vc, agentContext)))

      const allCredentialsVerified = results.every(verified => verified)
      if (!allCredentialsVerified) {
        throw new Error('One or more verifiable credentials failed signature verification.')
      }
    }
    return result.isValid
  } catch (error) {
    console.error('Error validating the proof:', error.message)
    return false
  }
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
 * Asynchronous document loader function for resolving JSON-LD contexts.
 *
 * This function returns predefined contexts for specific URLs used in
 * decentralized identity and verifiable credentials standards.
 *
 * @param {string} url - The URL of the JSON-LD context to retrieve.
 * @returns {Promise<{ document: any }>} A promise resolving to an object containing the context document.
 * @throws {Error} Throws an error if the requested context is not found.
 */
const documentLoader = async (url: string) => {
  if (url in DEFAULT_CONTEXTS) {
    return {
      contextUrl: null,
      documentUrl: url,
      document: DEFAULT_CONTEXTS[url as keyof typeof DEFAULT_CONTEXTS],
    }
  }
  const withoutFragment = url.split('#')[0]
  if (withoutFragment in DEFAULT_CONTEXTS) {
    return {
      contextUrl: null,
      documentUrl: url,
      document: DEFAULT_CONTEXTS[url as keyof typeof DEFAULT_CONTEXTS],
    }
  }
  throw new TrustError(TrustErrorCode.INVALID_REQUEST, `Context not found: ${url}`)
}

/**
 * Verifies the integrity of a given JSON schema string using a Subresource Integrity (SRI) digest.
 *
 * @param {string} schemaJson - The JSON schema as a string to be verified.
 * @param {string} expectedDigestSRI - The expected SRI digest in the format `{algorithm}-{hash}`.
 * @param {string} name - The name associated with the schema, used for error messages.
 * @throws {TrustError} Throws an error if the computed hash does not match the expected hash.
 */
export function verifyDigestSRI(schemaJson: string, expectedDigestSRI: string, name: string) {
  const [algorithm, expectedHash] = expectedDigestSRI.split('-')
  const computedHash = Buffer.from(hash(algorithm, JSON.stringify(JSON.parse(schemaJson)))).toString('base64')

  if (computedHash !== expectedHash) {
    throw new TrustError(TrustErrorCode.VERIFICATION_FAILED, `digestSRI verification failed for ${name}.`)
  }
}

const signatureSuiteRegistry = new SignatureSuiteRegistry([
  {
    suiteClass: Ed25519Signature2018,
    proofType: 'Ed25519Signature2018',
    verificationMethodTypes: [
      VERIFICATION_METHOD_TYPE_ED25519_VERIFICATION_KEY_2018,
      VERIFICATION_METHOD_TYPE_ED25519_VERIFICATION_KEY_2020,
    ],
    supportedPublicJwkTypes: [Ed25519PublicJwk],
  },
  {
    suiteClass: Ed25519Signature2020,
    proofType: 'Ed25519Signature2020',
    verificationMethodTypes: [VERIFICATION_METHOD_TYPE_ED25519_VERIFICATION_KEY_2020],
    supportedPublicJwkTypes: [Ed25519PublicJwk],
  },
])

/**
 * Verifies a presentation including the credentials it includes
 *
 * @param presentation the presentation to be verified
 * @returns the verification result
 */
async function verifyPresentation(
  options: W3cJsonLdVerifyPresentationOptions,
): Promise<W3cVerifyPresentationResult> {
  try {
    let proofs = options.presentation.proof

    if (!Array.isArray(proofs)) {
      proofs = [proofs]
    }
    if (options.purpose) {
      proofs = proofs.filter(proof => proof.proofPurpose === options.purpose.term)
    }

    const presentationSuites = proofs.map(proof => {
      const SuiteClass = signatureSuiteRegistry.getByProofType(proof.type).suiteClass
      return new SuiteClass({
        LDKeyClass: createKmsKeyPairClass(),
        proof: {
          verificationMethod: proof.verificationMethod,
        },
        date: proof.created,
        useNativeCanonize: false,
      })
    })

    const credentials = asArray(options.presentation.verifiableCredential)
    assertOnlyW3cJsonLdVerifiableCredentials(credentials)

    const credentialSuites = credentials.map(credential =>
      getSignatureSuitesForCredential(signatureSuiteRegistry, credential),
    )
    const allSuites = presentationSuites.concat(...credentialSuites)

    const verifyOptions: Record<string, unknown> = {
      presentation: JsonTransformer.toJSON(options.presentation),
      suite: allSuites,
      challenge: options.challenge,
      domain: options.domain,
      documentLoader,
    }

    // this is a hack because vcjs throws if purpose is passed as undefined or null
    if (options.purpose) {
      verifyOptions.presentationPurpose = options.purpose
    }

    const result = await vc.verify(verifyOptions)
    console.log(result)

    const { verified: isValid, ...remainingResult } = result

    // We map the result to our own result type to make it easier to work with
    // however, for now we just add a single vcJs validation result as we don't
    // have access to the internal validation results of vc-js
    return {
      isValid,
      validations: {
        vcJs: {
          isValid,
          ...remainingResult,
        },
      },
      error: result.error,
    }
  } catch (error) {
    return {
      isValid: false,
      validations: {},
      error,
    }
  }
}

/**
 * Verifies the signature(s) of a credential
 *
 * @param credential the credential to be verified
 * @returns the verification result
 */
async function verifyCredential(
  options: W3cJsonLdVerifyCredentialOptions,
): Promise<W3cVerifyCredentialResult> {
  try {
    const verifyCredentialStatus = options.verifyCredentialStatus ?? true

    const suites = getSignatureSuitesForCredential(signatureSuiteRegistry, options.credential)

    const verifyOptions: Record<string, unknown> = {
      credential: JsonTransformer.toJSON(options.credential),
      suite: suites,
      documentLoader,
      checkStatus: ({ credential }: { credential: W3cJsonCredential }) => {
        // Only throw error if credentialStatus is present
        if (verifyCredentialStatus && 'credentialStatus' in credential) {
          throw new Error('Verifying credential status for JSON-LD credentials is currently not supported')
        }
        return {
          verified: true,
        }
      },
    }

    // this is a hack because vcjs throws if purpose is passed as undefined or null
    if (options.proofPurpose) {
      verifyOptions.purpose = options.proofPurpose
    }

    const result = await vc.verifyCredential(verifyOptions)

    const { verified: isValid, ...remainingResult } = result

    if (!isValid) {
      console.debug(`Credential verification failed: ${result.error?.message}`, {
        stack: result.error?.stack,
      })
    }

    // We map the result to our own result type to make it easier to work with
    // however, for now we just add a single vcJs validation result as we don't
    // have access to the internal validation results of vc-js
    return {
      isValid,
      validations: {
        vcJs: {
          isValid,
          ...remainingResult,
        },
      },
      error: result.error,
    }
  } catch (error) {
    return {
      isValid: false,
      validations: {},
      error,
    }
  }
}

function getSignatureSuitesForCredential(
  signatureSuiteRegistry: SignatureSuiteRegistry,
  credential: W3cJsonLdVerifiableCredential,
) {
  // const WalletKeyPair = createKmsKeyPairClass(agentContext)

  let proofs = credential.proof

  if (!Array.isArray(proofs)) {
    proofs = [proofs]
  }

  return proofs.map(proof => {
    const SuiteClass = signatureSuiteRegistry.getByProofType(proof.type)?.suiteClass
    if (SuiteClass) {
      return new SuiteClass({
        LDKeyClass: createKmsKeyPairClass(),
        proof: {
          verificationMethod: proof.verificationMethod,
        },
        date: proof.created,
        useNativeCanonize: false,
      })
    }
  })
}

