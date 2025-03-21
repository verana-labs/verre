import { TrustedResolutionMetadata, TrustErrorCode } from '../types'

import { buildMetadata } from './helper'

export class TrustError extends Error {
  metadata: TrustedResolutionMetadata

  constructor(code: TrustErrorCode, message: string) {
    super(message)
    this.metadata = buildMetadata(code, message)
  }
}
