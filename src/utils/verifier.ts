import type { W3cJsonLdVerifiableCredential, W3cJsonLdVerifiablePresentation } from '@credo-ts/core'

import { createHash } from 'crypto'

import { purposes, suites, verify } from '../libraries'
import { TrustErrorCode } from '../types'

import { TrustError } from './trustError'

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
): Promise<boolean> {
  try {
    if (
      !document.proof ||
      !(document.type.includes('VerifiablePresentation') || document.type.includes('VerifiableCredential'))
    ) {
      throw new Error(
        'The document must be a Verifiable Presentation or Verifiable Credential with a valid proof.',
      )
    }
    const isPresentation = document.type.includes('VerifiablePresentation')

    const suite = new suites.LinkedDataSignature({
      /* suite options */
    })
    const purpose = isPresentation
      ? new purposes.AuthenticationProofPurpose()
      : new purposes.AssertionProofPurpose()

    const result = await verify({
      document,
      suite,
      purpose,
      documentLoader,
    })
    if (!result.verified) return false

    if (isPresentation && isVerifiablePresentation(document)) {
      const credentials = Array.isArray(document.verifiableCredential)
        ? document.verifiableCredential
        : [document.verifiableCredential]

      const jsonLdCredentials = credentials.filter((vc): vc is W3cJsonLdVerifiableCredential => 'proof' in vc)
      const results = await Promise.all(jsonLdCredentials.map(vc => verifySignature(vc)))

      const allCredentialsVerified = results.every(verified => verified)
      if (!allCredentialsVerified) {
        throw new Error('One or more verifiable credentials failed signature verification.')
      }
    }
    return result.verified
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
const documentLoader = async (url: string): Promise<{ document: any }> => {
  const contexts: Record<string, any> = {
    'https://www.w3.org/2018/credentials/v1': {},
    'https://w3id.org/did/v1': {},
    'https://w3id.org/security/suites/ed25519-2018/v1': {},
  }
  if (contexts[url]) {
    return { document: contexts[url] }
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
  const computedHash = createHash(algorithm).update(JSON.stringify(JSON.parse(schemaJson)), 'utf8').digest('base64')

  if (computedHash !== expectedHash) {
    throw new TrustError(TrustErrorCode.VERIFICATION_FAILED, `digestSRI verification failed for ${name}.`)
  }
}
