import { TrustedResolutionMetadata, TrustErrorCode, TrustStatus } from '../types'

export function buildMetadata(errorCode?: TrustErrorCode, errorMessage?: string): TrustedResolutionMetadata {
  if (!errorCode) {
    return {
      status: TrustStatus.RESOLVED,
      errorMessage,
    }
  }

  return {
    status: TrustStatus.ERROR,
    errorCode,
    errorMessage,
  }
}
