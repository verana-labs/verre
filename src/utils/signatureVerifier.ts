import type { W3cJsonLdVerifiablePresentation } from '@credo-ts/core'

import crypto from 'crypto'

import { purposes, suites, verify } from '../libraries'

/**
 * Validates the proof of a Linked Verifiable Presentation (VP).
 * @param {W3cJsonLdVerifiablePresentation} document - The Verifiable Presentation to validate.
 * @returns {Promise<boolean>} - True if the proof is valid, false otherwise.
 */
export async function verifyLinkedVP(document: W3cJsonLdVerifiablePresentation): Promise<boolean> {
  try {
    if (!document.proof) {
      throw new Error('The Verifiable Presentation does not contain a valid proof.')
    }
    const suite = new suites.LinkedDataSignature({
      /* suite options */
    })
    const purpose = new purposes.AssertionProofPurpose()

    console.log(document)
    const result = await verify({
      document,
      suite,
      purpose,
      documentLoader,
    })
    console.log(result)

    return result.verified
  } catch (error) {
    console.error('Error validating the proof:', error.message)
    return false
  }
}

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

export async function verifyDigestSRI(schemaUrl: string, expectedDigestSRI: string): Promise<boolean> {
  const [algorithm, expectedHash] = expectedDigestSRI.split('-')

  const response = await fetch(schemaUrl)
  if (!response.ok) throw new Error(`Failed to fetch schema: ${response.statusText}`)
  const schemaJson = await response.text()

  const computedHash = crypto.createHash(algorithm).update(schemaJson).digest('base64')
  return computedHash === expectedHash
}
