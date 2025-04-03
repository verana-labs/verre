import { TrustedResolutionMetadata, TrustErrorCode, TrustStatus } from '../types'

import { TrustError } from './trustError'

/**
 * Builds metadata for a trust resolution process.
 *
 * If no error code is provided, the status is set to `RESOLVED`.
 * Otherwise, it is set to `ERROR`, including the error details.
 *
 * @param errorCode - Optional error code indicating a trust validation failure.
 * @param errorMessage - Optional descriptive error message.
 * @returns The metadata containing the resolution status and error details if applicable.
 */
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

/**
 * Fetches and returns a schema from a given URL.
 *
 * The function performs an HTTP request to fetch the schema.
 * If the request fails, it throws a `TrustError` with details.
 *
 * @template T - The expected schema structure.
 * @param url - The URL to fetch the schema from.
 * @returns A promise resolving to the fetched schema.
 * @throws {TrustError} If the request fails.
 */
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
