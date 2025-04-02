import { TrustedResolutionMetadata, TrustErrorCode } from '../types'

import { buildMetadata } from './helper'

export class TrustError extends Error {
  metadata: TrustedResolutionMetadata

  constructor(code: TrustErrorCode, message: string) {
    super(message)
    this.metadata = buildMetadata(code, message)
  }
}

export function handleTrustError(error: unknown, extraData: Record<string, unknown> = {}) {
  if (error instanceof TrustError) {
    return { ...extraData, metadata: error.metadata }
  }
  return { ...extraData, metadata: buildMetadata(TrustErrorCode.INVALID, `Unexpected error: ${error}`) }
}
