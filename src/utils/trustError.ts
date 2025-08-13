import { DIDDocument } from 'did-resolver'

import { TrustResolutionMetadata, TrustErrorCode, TrustResolutionOutcome } from '../types'

import { buildMetadata } from './helper'

/**
 * Custom error class for handling trust-related errors.
 * Extends the standard `Error` class and includes metadata for detailed resolution information.
 */
export class TrustError extends Error {
  metadata: TrustResolutionMetadata

  constructor(code: TrustErrorCode, message: string) {
    super(message)
    this.metadata = buildMetadata(code, message)
  }
}

/**
 * Handles trust errors and ensures metadata is properly included in the response.
 *
 * @param {unknown} error - The error to be processed.
 * @param {DIDDocument} [didDocument] - An optional DID Document associated with the error.
 * @returns {object} An object containing the `didDocument` (if provided) and the error metadata.
 */
export function handleTrustError(error: unknown, didDocument?: DIDDocument) {
  if (error instanceof TrustError) {
    return {
      didDocument,
      outcome: TrustResolutionOutcome.INVALID,
      verified: false,
      metadata: error.metadata,
    }
  }
  return {
    didDocument,
    verified: false,
    outcome: TrustResolutionOutcome.INVALID,
    metadata: buildMetadata(TrustErrorCode.INVALID, `Unexpected error: ${error}`),
  }
}
