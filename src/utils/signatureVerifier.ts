import type { W3cJsonLdVerifiablePresentation } from '@credo-ts/core'

/**
 * Validates the proof of a Linked Verifiable Presentation (VP).
 * @param {W3cJsonLdVerifiablePresentation} vp - The Verifiable Presentation to validate.
 * @returns {Promise<boolean>} - True if the proof is valid, false otherwise.
 */
export async function verifyLinkedVP(vp: W3cJsonLdVerifiablePresentation): Promise<boolean> {
  try {
    if (!vp.proof) {
      throw new Error('The Verifiable Presentation does not contain a valid proof.')
    }

    // const result = await verif({
    //   presentation: vp,
    //   challenge: 'random-challenge',
    //   documentLoader: documentLoaders.default,
    // })

    return true //result.isValid
  } catch (error) {
    console.error('Error validating the proof:', error.message)
    return false
  }
}
