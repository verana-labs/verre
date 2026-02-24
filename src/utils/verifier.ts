import {
  AgentContext,
  JsonTransformer,
  W3cCredentialService,
  W3cJsonLdVerifiableCredential,
  W3cJsonLdVerifiablePresentation,
} from '@credo-ts/core'
import { Buffer } from 'buffer/'

import { purposes } from '../libraries'
import { TrustErrorCode, IVerreLogger } from '../types'

import { hash } from './crypto'
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
  agentContext: AgentContext,
  logger: IVerreLogger,
): Promise<{ result: boolean; error?: string }> {
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

    const w3c = await agentContext.dependencyManager.resolve(W3cCredentialService)
    const result = isPresentation
      ? await w3c?.verifyPresentation(agentContext, {
          presentation: JsonTransformer.fromJSON(document, W3cJsonLdVerifiablePresentation),
          purpose: new purposes.AssertionProofPurpose(),
          challenge: '', // It is currently mandatory in Credo API
        })
      : await w3c?.verifyCredential(agentContext, {
          credential: JsonTransformer.fromJSON(document, W3cJsonLdVerifiableCredential),
          proofPurpose: new purposes.AssertionProofPurpose(),
        })
    if (!result.isValid) {
      const error = JSON.stringify(result.validations.vcJs?.error)
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
      const results = await Promise.all(
        jsonLdCredentials.map(vc => verifySignature(vc, agentContext, logger)),
      )

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

  const computedHash = Buffer.from(hash(algorithm, rawContent)).toString('base64')
  logger.debug('Computing hash', { computedHash: `${algorithm}-${computedHash}` })

  if (computedHash !== expectedHash) {
    throw new TrustError(
      TrustErrorCode.VERIFICATION_FAILED,
      `digestSRI verification failed for ${rawContent}. Computed: ${computedHash}, Expected: ${expectedHash}`,
    )
  }

  logger.debug('Digest SRI verified successfully')
}
