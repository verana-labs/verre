import { parseDid } from '@credo-ts/core'
import { TrustResolutionMetadata, TrustErrorCode } from '../types'

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
export function buildMetadata(errorCode: TrustErrorCode, errorMessage: string): TrustResolutionMetadata {
  return {
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

/**
 * Fetches and returns the raw text content from a given URL.
 *
 * This is useful when byte-level integrity of the response matters,
 * such as when verifying SRI digests against the original content.
 *
 * @param url - The URL to fetch the data from.
 * @returns A promise resolving to the raw response text.
 * @throws {TrustError} If the HTTP request fails.
 */
export async function fetchText(url: string): Promise<string> {
  const response = await fetch(url)

  if (!response.ok) {
    throw new TrustError(
      TrustErrorCode.INVALID_REQUEST,
      `Failed to fetch data from ${url}: ${response.status} ${response.statusText}`,
    )
  }

  return response.text()
}

// TODO: Remove when the TR supports the WebVH DID resolution method
export function getWebDid(did: string) {
  const parsedDid = parseDid(did)

  if (parsedDid.method === 'web') return did
  if (parsedDid.method === 'webvh') return `did:web:${parsedDid.id.split(':')[1]}`
  throw new TrustError(TrustErrorCode.NOT_SUPPORTED, `DID method not supported`)
}
