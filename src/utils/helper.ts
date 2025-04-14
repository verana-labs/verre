import { TrustResolutionMetadata, TrustErrorCode, TrustStatus } from '../types'

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
export function buildMetadata(errorCode?: TrustErrorCode, errorMessage?: string): TrustResolutionMetadata {
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
 * Fetches and returns JSON data from a given URL.
 *
 * Performs an HTTP request and attempts to parse the response as JSON.
 * If the request fails, it throws a `TrustError` with relevant details.
 *
 * @template T - The expected structure of the JSON response.
 * @param url - The URL to fetch the data from.
 * @returns A promise resolving to the parsed JSON data.
 * @throws {TrustError} If the HTTP request fails.
 */
export async function fetchJson<T = any>(url: string): Promise<T> {
  const response = await fetch(url)

  if (!response.ok) {
    throw new TrustError(
      TrustErrorCode.INVALID_REQUEST,
      `Failed to fetch data from ${url}: ${response.status} ${response.statusText}`,
    )
  }

  return response.json() as T
}
