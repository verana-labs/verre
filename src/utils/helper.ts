import { TrustedResolutionMetadata, TrustErrorCode, TrustStatus } from '../types'

import { TrustError } from './trustError'

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

export async function fetchSchema<T = any>(url: string): Promise<T> {
  const response = await fetch(url)

  if (!response.ok) {
    throw new TrustError(
      TrustErrorCode.INVALID_REQUEST,
      `Failed to fetch schema from ${url}: ${response.status} ${response.statusText}`,
    )
  }
  return response.json() as T
}
