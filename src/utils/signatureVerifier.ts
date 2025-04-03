import type { W3cJsonLdVerifiablePresentation } from '@credo-ts/core'

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
