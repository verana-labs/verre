import type { W3cJsonLdVerifiablePresentation } from '@credo-ts/core'

import { createHash } from 'crypto'

import { purposes, suites, verify } from '../libraries'
import { TrustErrorCode } from '../types'

import { TrustError } from './trustError'

/**
 * Validates the proof of a Linked Verifiable Presentation (VP).
 * @param {W3cJsonLdVerifiablePresentation} document - The Verifiable Presentation to validate.
 * @returns {Promise<boolean>} - True if the proof is valid, false otherwise.
 */
export async function verifySignature(document: W3cJsonLdVerifiablePresentation): Promise<boolean> {
  try {
    if (!document.proof) {
      throw new Error('The Verifiable Presentation does not contain a valid proof.')
    }
    const suite = new suites.LinkedDataSignature({
      /* suite options */
    })
    const purpose = new purposes.AssertionProofPurpose()

    const result = await verify({
      document,
      suite,
      purpose,
      documentLoader,
    })

    return result.verified
  } catch (error) {
    console.error('Error validating the proof:', error.message)
    return false
  }
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
  throw new Error(`Context not found: ${url}`)
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
  const computedHash = createHash(algorithm).update(schemaJson).digest('base64')

  if (computedHash !== expectedHash) {
    throw new TrustError(TrustErrorCode.VERIFICATION_FAILED, `digestSRI verification failed for ${name}.`)
  }
}
