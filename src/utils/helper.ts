import { TrustResolutionMetadata, TrustErrorCode, TrustResolutionCache, TrustResolution } from '../types.js'

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

// ---------------------------------------------------------------------------
// HTTP fetch helpers with a default timeout
// ---------------------------------------------------------------------------
//
// Node's global `fetch` has no default request deadline: a host that
// black-holes the TCP connection (silent VPN, dropped packets, hung
// middlebox) causes the returned promise to pend forever. That
// starves every caller that awaits the fetch — most notably a serial
// DID resolution loop where one unreachable DID stalls every
// subsequent one.
//
// To avoid this footgun we wrap every `fetch(...)` call with an
// `AbortSignal.timeout(...)`. The timeout is read from
// `VERRE_HTTP_TIMEOUT_MS` at call time (not at module load) so tests
// and consumers can override it without re-importing the module.
// Setting the value to `0` or a negative number disables the timeout
// for the duration of the call, which is useful for environments
// where the caller supplies their own external deadline.

/**
 * Default HTTP timeout applied to `fetchJson` / `fetchText` when the
 * `VERRE_HTTP_TIMEOUT_MS` environment variable is unset.
 *
 * Exposed for tests.
 */
export const DEFAULT_FETCH_TIMEOUT_MS = 15_000

/**
 * Resolve the active HTTP timeout from the environment, falling back to
 * `DEFAULT_FETCH_TIMEOUT_MS`.
 *
 * A parsed value of `0` or any negative number disables the timeout
 * (returns `null`), letting a specific caller skip the wrapper.
 * Non-numeric input is treated as "unset" and silently falls back to
 * the default rather than throwing at call time.
 */
function resolveFetchTimeoutMs(): number | null {
  const raw = process.env.VERRE_HTTP_TIMEOUT_MS
  if (raw === undefined || raw === '') return DEFAULT_FETCH_TIMEOUT_MS
  const parsed = Number(raw)
  if (!Number.isFinite(parsed)) return DEFAULT_FETCH_TIMEOUT_MS
  if (parsed <= 0) return null
  return parsed
}

/**
 * Shared error-mapping for both fetch helpers. Translates any failure
 * of the underlying `fetch(...)` call — `AbortError` from the timeout,
 * DNS / connection errors, TLS errors — into a `TrustError` tagged
 * with `DEREFERENCE_FAILED`, which is the code the rest of verre
 * already reserves for HTTP / network errors at the VP layer.
 */
function toDereferenceError(url: string, error: unknown, timeoutMs: number | null): TrustError {
  const err = error as { name?: string; code?: string; message?: string; cause?: unknown }
  const isTimeout = err?.name === 'TimeoutError' || err?.name === 'AbortError'

  if (isTimeout && timeoutMs !== null) {
    return new TrustError(
      TrustErrorCode.DEREFERENCE_FAILED,
      `HTTP request to ${url} timed out after ${timeoutMs}ms`,
    )
  }

  const causeMsg = err?.message ?? String(error)
  return new TrustError(
    TrustErrorCode.DEREFERENCE_FAILED,
    `HTTP request to ${url} failed: ${causeMsg}`,
  )
}

/**
 * Fetches and returns JSON data from a given URL.
 *
 * Performs an HTTP request and attempts to parse the response as JSON.
 * A default timeout (`VERRE_HTTP_TIMEOUT_MS`, `15000` ms) is applied so
 * unreachable servers do not hang the caller indefinitely; set the env
 * var to `0` to opt out.
 *
 * @template T - The expected structure of the JSON response.
 * @param url - The URL to fetch the data from.
 * @returns A promise resolving to the parsed JSON data.
 * @throws {TrustError} `DEREFERENCE_FAILED` if the underlying fetch
 *         times out or errors at the network layer; `INVALID_REQUEST`
 *         if the server responds with a non-2xx status.
 */
export async function fetchJson<T = any>(url: string): Promise<T> {
  const timeoutMs = resolveFetchTimeoutMs()
  const signal = timeoutMs !== null ? AbortSignal.timeout(timeoutMs) : undefined

  let response: Response
  try {
    response = await fetch(url, signal ? { signal } : undefined)
  } catch (error) {
    throw toDereferenceError(url, error, timeoutMs)
  }

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
 * such as when verifying SRI digests against the original content. A
 * default timeout (`VERRE_HTTP_TIMEOUT_MS`, `15000` ms) is applied; set
 * the env var to `0` to opt out.
 *
 * @param url - The URL to fetch the data from.
 * @returns A promise resolving to the raw response text.
 * @throws {TrustError} `DEREFERENCE_FAILED` if the underlying fetch
 *         times out or errors at the network layer; `INVALID_REQUEST`
 *         if the server responds with a non-2xx status.
 */
export async function fetchText(url: string): Promise<string> {
  const timeoutMs = resolveFetchTimeoutMs()
  const signal = timeoutMs !== null ? AbortSignal.timeout(timeoutMs) : undefined

  let response: Response
  try {
    response = await fetch(url, signal ? { signal } : undefined)
  } catch (error) {
    throw toDereferenceError(url, error, timeoutMs)
  }

  if (!response.ok) {
    throw new TrustError(
      TrustErrorCode.INVALID_REQUEST,
      `Failed to fetch data from ${url}: ${response.status} ${response.statusText}`,
    )
  }

  return response.text()
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
