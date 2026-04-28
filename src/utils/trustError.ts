import { DIDDocument } from 'did-resolver'

import {
  TrustResolutionMetadata,
  TrustErrorCode,
  TrustResolutionOutcome,
  VpOutcome,
  VpOutcomeWithError,
} from '../types.js'

import { buildMetadata } from './helper.js'

/**
 * Custom error class for handling trust-related errors.
 *
 * Extends the standard `Error` class with `metadata` carrying the
 * coarse-grained outcome of the failure. May optionally carry the
 * per-VP / per-credential outcome arrays accumulated by
 * `processDidDocument` so that they survive to `handleTrustError`
 * (and thence to the final `TrustResolution` returned to callers
 * even on the invalid path).
 */
export class TrustError extends Error {
  metadata: TrustResolutionMetadata
  /** Optional partial-progress accumulator surfaced on the error path. */
  validPresentations?: VpOutcome[]
  /** Optional partial-progress accumulator surfaced on the error path. */
  invalidPresentations?: VpOutcomeWithError[]

  constructor(code: TrustErrorCode, message: string) {
    super(message)
    this.metadata = buildMetadata(code, message)
  }
}

/**
 * Handles trust errors and ensures metadata is properly included in the response.
 *
 * When the thrown `TrustError` carries `validPresentations` /
 * `invalidPresentations` arrays (attached by `processDidDocument` on the
 * partial-failure path), they are forwarded onto the resulting
 * `TrustResolution` so that consumers can still inspect which VPs
 * succeeded and which failed even though the overall resolution did not
 * yield a verified service + serviceProvider pair.
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
      validPresentations: error.validPresentations,
      invalidPresentations: error.invalidPresentations,
    }
  }
  return {
    didDocument,
    verified: false,
    outcome: TrustResolutionOutcome.INVALID,
    metadata: buildMetadata(TrustErrorCode.INVALID, `Unexpected error: ${error}`),
  }
}
