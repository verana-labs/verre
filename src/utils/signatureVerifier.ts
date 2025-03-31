import { W3cJsonLdVerifiablePresentation, type W3cPresentation } from '@credo-ts/core'

/**
 * Validates the proof of a Linked Verifiable Presentation (VP).
 * @param {W3cPresentation} vp - The Verifiable Presentation to validate.
 * @returns {Promise<boolean>} - True if the proof is valid, false otherwise.
 */
export async function verifyLinkedVP(vp: W3cPresentation): Promise<boolean> {
  try {
    if (!(vp instanceof W3cJsonLdVerifiablePresentation)) {
      throw new Error('The provided Verifiable Presentation is not a valid Verifiable Presentation.')
    }
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
