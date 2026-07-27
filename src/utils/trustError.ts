import { DIDDocument } from 'did-resolver'

import {
  TrustResolutionMetadata,
  TrustErrorCode,
  TrustResolutionOutcome,
  FailedCredential,
} from '../types.js'

import { buildMetadata } from './helper.js'

/**
 * Custom error class for handling trust-related errors.
 * Extends the standard `Error` class and includes metadata for detailed resolution information.
 */
export class TrustError extends Error {
  metadata: TrustResolutionMetadata
  failedCredentials?: FailedCredential[]

  constructor(code: TrustErrorCode, message: string, failedCredentials?: FailedCredential[]) {
    super(message)
    this.metadata = buildMetadata(code, message)
    if (failedCredentials?.length) this.failedCredentials = failedCredentials
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
      ...(error.failedCredentials ? { failedCredentials: error.failedCredentials } : {}),
    }
  }
  return {
    didDocument,
    verified: false,
    outcome: TrustResolutionOutcome.INVALID,
    metadata: buildMetadata(TrustErrorCode.INVALID, `Unexpected error: ${error}`),
  }
}
