import { DEFAULT_SCHEMAS } from '../libraries/defaultSchemas.js'
import { TrustResolutionMetadata, TrustErrorCode, TrustResolutionCache, TrustResolution } from '../types.js'

import { computeDigestSRI } from './crypto.js'
import { TrustError } from './trustError.js'

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
 * Maps a failed HTTP status to the error code of the fetch.
 *
 * A rate limit (429) or a server failure (5xx) is transient, so the caller can retry it later.
 * Any other failed status is a final `INVALID_REQUEST`.
 *
 * @param status - The HTTP status of the failed response.
 * @returns `UNAVAILABLE` for a transient failure, `INVALID_REQUEST` otherwise.
 */
export function fetchFailureCode(status: number): TrustErrorCode {
  return status === 429 || status >= 500 ? TrustErrorCode.UNAVAILABLE : TrustErrorCode.INVALID_REQUEST
}

/**
 * Performs an HTTP request and returns the successful response.
 *
 * A network error is a transient `UNAVAILABLE` failure, as is a 429 or 5xx status.
 *
 * @param url - The URL to fetch.
 * @returns A promise resolving to the successful response.
 * @throws {TrustError} If the request fails or the response status is not 2xx.
 */
async function fetchResponse(url: string): Promise<Response> {
  let response: Response
  try {
    response = await fetch(url)
  } catch (error) {
    throw new TrustError(TrustErrorCode.UNAVAILABLE, `Failed to fetch data from ${url}: ${error}`)
  }

  if (!response.ok) {
    throw new TrustError(
      fetchFailureCode(response.status),
      `Failed to fetch data from ${url}: ${response.status} ${response.statusText}`,
    )
  }

  return response
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
  const response = await fetchResponse(url)
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
  const response = await fetchResponse(url)
  return response.text()
}

/** How long a fetched schema document stays in the in-process cache. */
const SCHEMA_CACHE_TTL_MS = 60 * 60 * 1000

const schemaCache = new Map<string, { value: Promise<string>; expiresAt: number }>()

/**
 * Empties the in-process cache of schema documents.
 */
export function clearSchemaCache() {
  schemaCache.clear()
}

/**
 * Returns the raw text of a JSON Schema document that a `credentialSchema` references.
 *
 * A bundled copy (`DEFAULT_SCHEMAS`) is served without network access when it matches the pinned
 * `digestSRI`, so a fixed W3C document never depends on the availability of w3.org. Any other document
 * is fetched once over HTTP and kept in an in-process cache. A cached copy is reused only while it
 * matches the pinned digest, and a failed fetch is never cached. Concurrent requests for one URL share
 * one fetch.
 *
 * The caller still verifies the returned text with `verifyDigestSRI`.
 *
 * @param url - The URL of the schema document.
 * @param digestSRI - The digest that the credential pins for the document, if any.
 * @returns A promise resolving to the raw text of the document.
 * @throws {TrustError} If the HTTP request fails.
 */
export async function fetchSchemaText(url: string, digestSRI?: string): Promise<string> {
  const matches = (text: string) => {
    if (!digestSRI) return true
    // an unsupported algorithm is a mismatch here; verifyDigestSRI reports it to the caller
    try {
      return computeDigestSRI(digestSRI.split('-')[0], text) === digestSRI
    } catch {
      return false
    }
  }

  const bundled = DEFAULT_SCHEMAS[url]
  if (bundled !== undefined && matches(bundled)) return bundled

  const cached = schemaCache.get(url)
  if (cached && Date.now() <= cached.expiresAt) {
    const text = await cached.value
    if (matches(text)) return text
  }

  const entry = { value: fetchText(url), expiresAt: Date.now() + SCHEMA_CACHE_TTL_MS }
  schemaCache.set(url, entry)
  try {
    const text = await entry.value
    // a copy that fails its pin is not worth keeping; verifyDigestSRI reports the mismatch
    if (!matches(text) && schemaCache.get(url) === entry) schemaCache.delete(url)
    return text
  } catch (error) {
    if (schemaCache.get(url) === entry) schemaCache.delete(url)
    throw error
  }
}

/**
 * In-memory implementation of `TrustResolutionCache` backed by a `Map`.
 *
 * Useful for avoiding redundant resolutions within the same process lifetime.
 * For persistent or distributed caching, provide your own `TrustResolutionCache` implementation (e.g. Redis).
 */
export class InMemoryCache implements TrustResolutionCache<string, Promise<TrustResolution>> {
  private map = new Map<string, { value: Promise<TrustResolution>; expiresAt: number }>()
  private ttlMs: number

  constructor(ttlMs: number = 5 * 60 * 1000) {
    this.ttlMs = ttlMs
  }

  get(key: string): Promise<TrustResolution> | undefined {
    const entry = this.map.get(key)
    if (!entry) return undefined
    if (Date.now() > entry.expiresAt) {
      this.map.delete(key)
      return undefined
    }
    return entry.value
  }

  set(key: string, value: Promise<TrustResolution>) {
    this.map.set(key, { value, expiresAt: Date.now() + this.ttlMs })
  }
  delete(key: string) {
    this.map.delete(key)
  }
  clear() {
    this.map.clear()
  }
}
