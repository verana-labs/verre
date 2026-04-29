import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { DEFAULT_FETCH_TIMEOUT_MS, fetchJson, fetchText } from '../../src/utils/helper'
import { TrustError } from '../../src/utils/trustError'
import { TrustErrorCode } from '../../src/types'

// Each test installs a deterministic stub for the global `fetch` so we
// never touch the network. The stub mirrors only the surface area both
// helpers consume: a Promise that resolves to a `Response`-shaped object
// with `ok`, `status`, `statusText`, `json()`, `text()`, *and* respects
// the AbortSignal passed in `init.signal`.

interface FakeResponseInit {
  ok?: boolean
  status?: number
  statusText?: string
  body?: unknown
  delayMs?: number
}

/**
 * Build a fetch mock that resolves after `delayMs`, but rejects with an
 * `AbortError` (matching native `fetch`) if the caller's AbortSignal
 * fires first. This lets tests exercise both the timeout-fires path
 * and the no-timeout path through the exact same call surface.
 */
function makeFetchMock(init: FakeResponseInit) {
  const { ok = true, status = 200, statusText = 'OK', body = {}, delayMs = 0 } = init
  return vi.fn(async (_url: string, options?: { signal?: AbortSignal }) => {
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(resolve, delayMs)
      if (options?.signal) {
        if (options.signal.aborted) {
          clearTimeout(timeout)
          // `AbortSignal.timeout(...)` raises `TimeoutError`, manual aborts raise `AbortError`.
          const reason = (options.signal as AbortSignal & { reason?: unknown }).reason
          const err = reason instanceof Error ? reason : new DOMException('Aborted', 'AbortError')
          reject(err)
          return
        }
        options.signal.addEventListener('abort', () => {
          clearTimeout(timeout)
          const reason = (options.signal as AbortSignal & { reason?: unknown }).reason
          const err = reason instanceof Error ? reason : new DOMException('Aborted', 'AbortError')
          reject(err)
        })
      }
    })
    return {
      ok,
      status,
      statusText,
      json: async () => body,
      text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
    }
  })
}

const ORIGINAL_FETCH = globalThis.fetch
const ORIGINAL_TIMEOUT = process.env.VERRE_HTTP_TIMEOUT_MS

beforeEach(() => {
  // Reset the env between tests so order does not matter.
  delete process.env.VERRE_HTTP_TIMEOUT_MS
})

afterEach(() => {
  globalThis.fetch = ORIGINAL_FETCH
  if (ORIGINAL_TIMEOUT === undefined) {
    delete process.env.VERRE_HTTP_TIMEOUT_MS
  } else {
    process.env.VERRE_HTTP_TIMEOUT_MS = ORIGINAL_TIMEOUT
  }
  vi.restoreAllMocks()
})

describe('fetchJson', () => {
  it('returns the parsed body on a fast 2xx response', async () => {
    globalThis.fetch = makeFetchMock({ body: { hello: 'world' }, delayMs: 0 }) as unknown as typeof fetch
    const result = await fetchJson<{ hello: string }>('https://example.com/x')
    expect(result).toEqual({ hello: 'world' })
  })

  it('throws DEREFERENCE_FAILED with a "timed out after Nms" message when the server hangs past the timeout', async () => {
    process.env.VERRE_HTTP_TIMEOUT_MS = '50'
    // The mock waits longer than the configured timeout so the AbortSignal fires first.
    globalThis.fetch = makeFetchMock({ delayMs: 500 }) as unknown as typeof fetch

    let caught: unknown
    try {
      await fetchJson('https://slow.example.com/x')
    } catch (e) {
      caught = e
    }

    expect(caught).toBeInstanceOf(TrustError)
    const tErr = caught as TrustError
    expect(tErr.metadata.errorCode).toBe(TrustErrorCode.DEREFERENCE_FAILED)
    expect(tErr.message).toContain('timed out after 50ms')
    expect(tErr.message).toContain('https://slow.example.com/x')
  })

  it('respects VERRE_HTTP_TIMEOUT_MS=0 by skipping the timeout entirely', async () => {
    process.env.VERRE_HTTP_TIMEOUT_MS = '0'
    // Without a timeout, even a 100ms delay completes successfully.
    globalThis.fetch = makeFetchMock({ body: { ok: true }, delayMs: 100 }) as unknown as typeof fetch

    const result = await fetchJson<{ ok: boolean }>('https://nolimit.example.com/x')
    expect(result).toEqual({ ok: true })
  })

  it('falls back to the default timeout when VERRE_HTTP_TIMEOUT_MS is unset (default = 15000ms)', async () => {
    expect(process.env.VERRE_HTTP_TIMEOUT_MS).toBeUndefined()
    expect(DEFAULT_FETCH_TIMEOUT_MS).toBe(15_000)

    // Verify the helper does pass *some* AbortSignal whose timeout reflects the default;
    // we don't actually wait 15s — we simply assert the fetch was called with a signal.
    const stub = vi.fn(async (_url: string, options?: { signal?: AbortSignal }) => {
      expect(options?.signal).toBeDefined()
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({ ok: true }),
        text: async () => '{"ok":true}',
      }
    })
    globalThis.fetch = stub as unknown as typeof fetch

    await fetchJson('https://default.example.com/x')
    expect(stub).toHaveBeenCalledOnce()
  })

  it('falls back to the default timeout when VERRE_HTTP_TIMEOUT_MS is non-numeric', async () => {
    process.env.VERRE_HTTP_TIMEOUT_MS = 'not-a-number'
    const stub = vi.fn(async (_url: string, options?: { signal?: AbortSignal }) => {
      expect(options?.signal).toBeDefined()
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({ ok: true }),
        text: async () => '{"ok":true}',
      }
    })
    globalThis.fetch = stub as unknown as typeof fetch
    await fetchJson('https://example.com/x')
    expect(stub).toHaveBeenCalledOnce()
  })

  it('still throws INVALID_REQUEST on a non-2xx response (existing behaviour)', async () => {
    globalThis.fetch = makeFetchMock({ ok: false, status: 404, statusText: 'Not Found' }) as unknown as typeof fetch

    await expect(fetchJson('https://missing.example.com/x')).rejects.toMatchObject({
      metadata: { errorCode: TrustErrorCode.INVALID_REQUEST },
    })
  })

  it('maps generic network errors (e.g. ECONNREFUSED) to DEREFERENCE_FAILED', async () => {
    globalThis.fetch = vi.fn(async () => {
      throw Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:9999'), { code: 'ECONNREFUSED' })
    }) as unknown as typeof fetch

    let caught: unknown
    try {
      await fetchJson('https://refused.example.com/x')
    } catch (e) {
      caught = e
    }

    expect(caught).toBeInstanceOf(TrustError)
    const tErr = caught as TrustError
    expect(tErr.metadata.errorCode).toBe(TrustErrorCode.DEREFERENCE_FAILED)
    expect(tErr.message).toContain('failed:')
    expect(tErr.message).toContain('ECONNREFUSED')
  })
})

describe('fetchText', () => {
  it('returns the raw body on a fast 2xx response', async () => {
    globalThis.fetch = makeFetchMock({ body: 'plain text payload', delayMs: 0 }) as unknown as typeof fetch
    const result = await fetchText('https://example.com/x')
    expect(result).toBe('plain text payload')
  })

  it('throws DEREFERENCE_FAILED with a timeout message on hang', async () => {
    process.env.VERRE_HTTP_TIMEOUT_MS = '40'
    globalThis.fetch = makeFetchMock({ delayMs: 500 }) as unknown as typeof fetch

    let caught: unknown
    try {
      await fetchText('https://slow.example.com/x')
    } catch (e) {
      caught = e
    }

    expect(caught).toBeInstanceOf(TrustError)
    const tErr = caught as TrustError
    expect(tErr.metadata.errorCode).toBe(TrustErrorCode.DEREFERENCE_FAILED)
    expect(tErr.message).toContain('timed out after 40ms')
  })

  it('still throws INVALID_REQUEST on a non-2xx response (existing behaviour)', async () => {
    globalThis.fetch = makeFetchMock({ ok: false, status: 500, statusText: 'Server Error' }) as unknown as typeof fetch
    await expect(fetchText('https://broken.example.com/x')).rejects.toMatchObject({
      metadata: { errorCode: TrustErrorCode.INVALID_REQUEST },
    })
  })
})
