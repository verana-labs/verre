import { DIDDocument } from 'did-resolver'

import { TrustedResolutionMetadata, TrustErrorCode } from '../types'

import { buildMetadata } from './helper'

/**
 * Custom error class for handling trust-related errors.
 * Extends the standard `Error` class and includes metadata for detailed resolution information.
 */
export class TrustError extends Error {
  metadata: TrustedResolutionMetadata

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
    return { didDocument, metadata: error.metadata }
  }
  return { didDocument, metadata: buildMetadata(TrustErrorCode.INVALID, `Unexpected error: ${error}`) }
}
