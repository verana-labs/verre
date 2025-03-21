import { TrustedResolutionMetadata, TrustErrorCode, TrustStatus } from '../types'

export function buildMetadata(errorCode?: TrustErrorCode, content?: string): TrustedResolutionMetadata {
  if (!errorCode) {
    return {
      status: TrustStatus.RESOLVED,
      content,
    }
  }

  return {
    status: TrustStatus.ERROR,
    errorCode,
    content,
  }
}
