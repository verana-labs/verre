import { ed25519 } from '@noble/curves/ed25519.js'
import { DIDResolutionOptions, DIDResolutionResult, DIDResolver, Resolver } from 'did-resolver'
import { resolveDID as resolveWebVh } from 'didwebvh-ts'
import * as didWeb from 'web-did-resolver'

const ed25519Verifier = {
  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    return ed25519.verify(signature, message, publicKey)
  },
}

/**
 * Map a raw error code emitted by `didwebvh-ts` (or an inferred one based on
 * the error message for thrown exceptions) to a W3C DID Resolution error code
 * as defined in https://www.w3.org/TR/did-core/#did-resolution-metadata.
 *
 * The mapping is intentionally conservative:
 *   - `INVALID_DID` (and its variants: bad hash chain, bad signature, bad SCID,
 *     deactivated with wrong updateKey, etc.) → `invalidDid`. The DID *is*
 *     present — the log fetched with HTTP 200 — but failed cryptographic or
 *     structural validation.
 *   - `NOT_FOUND` (and fetch-level failures: 404, ENOTFOUND, ECONNREFUSED) →
 *     `notFound`. Nothing at the DID location to validate.
 *   - Anything else → `internalError`, which preserves the legacy catch-all
 *     behaviour so unexpected failures are not silently classified as missing.
 *
 * Keeping the detail on `didDocumentMetadata` (see `webVhDidResolver`) lets
 * callers surface the underlying `problemDetails.detail` — e.g.
 * `"Hash chain broken at '2-Qm…'"` — in downstream diagnostics.
 */
function mapWebvhErrorToW3c(rawCode: string | undefined, message: string | undefined): string {
  const code = rawCode?.toUpperCase() ?? ''
  if (code === 'INVALID_DID' || code.startsWith('INVALID_')) return 'invalidDid'
  if (code === 'NOT_FOUND') return 'notFound'

  // Heuristic fallback for thrown exceptions that do not carry a code: the
  // didwebvh-ts library throws plain Errors for fetch failures and similar.
  const haystack = `${code} ${message ?? ''}`.toLowerCase()
  if (/not[_\s-]?found|404|enotfound|econnrefused|dns|timed?\s?out/.test(haystack)) {
    return 'notFound'
  }
  if (/invalid|hash\s?chain|signature|scid|proof|witness|updatekey/.test(haystack)) {
    return 'invalidDid'
  }
  return 'internalError'
}

const webVhDidResolver: DIDResolver = async (did: string): Promise<DIDResolutionResult> => {
  try {
    const result = await resolveWebVh(did, { verifier: ed25519Verifier })

    // didwebvh-ts may resolve successfully with either a populated `doc` or
    // with `meta.error` set when validation fails (e.g. broken hash chain).
    // The legacy wrapper collapsed both cases to `notFound`, which erased the
    // distinction between "DID log missing" and "DID log invalid" and made
    // diagnosis on the downstream verana-resolver impossible. We now preserve
    // the specific W3C error code and carry the full `problemDetails` through
    // `didDocumentMetadata` so consumers can surface the underlying cause.
    if (result.meta?.error || !result.doc) {
      const rawCode = (result.meta?.error as string | undefined) ?? undefined
      const detail =
        (result.meta as { problemDetails?: { detail?: string } } | undefined)?.problemDetails?.detail ?? undefined
      const w3cError = mapWebvhErrorToW3c(rawCode, detail)
      return {
        didResolutionMetadata: {
          error: w3cError,
          // Preserve the original didwebvh-ts error code alongside the W3C
          // code so downstream consumers can still distinguish e.g. a bad
          // hash chain from an invalid signature without parsing text.
          ...(rawCode !== undefined ? { message: detail ?? rawCode } : {}),
        },
        didDocument: null,
        didDocumentMetadata: result.meta ?? {},
      }
    }

    return {
      didResolutionMetadata: {},
      didDocument: result.doc,
      didDocumentMetadata: result.meta ?? {},
    }
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : String(e)
    // Unexpected throw — classify based on the thrown message so that an
    // ENOTFOUND / 404 on the log fetch still ends up as `notFound`, while a
    // thrown validation error surfaces as `invalidDid` rather than being
    // swallowed into a generic `internalError`.
    const w3cError = mapWebvhErrorToW3c(undefined, message)
    return {
      didResolutionMetadata: { error: w3cError, message },
      didDocument: null,
      didDocumentMetadata: {},
    }
  }
}

export const baseResolver = new Resolver({
  ...didWeb.getResolver(),
  webvh: webVhDidResolver,
})

export const resolverInstance = createCachedResolver(baseResolver)

export type CachedResolver = Resolver & { clear: () => void }
export function createCachedResolver(innerResolver: Resolver, ttlMs: number = 5 * 60 * 1000): CachedResolver {
  const cache = new Map<string, { promise: Promise<DIDResolutionResult>; expiresAt: number }>()

  const cachedResolver = {
    ...innerResolver,
    resolve: async (didUrl: string, options?: DIDResolutionOptions): Promise<DIDResolutionResult> => {
      const baseDid = didUrl.split(/[#?]/)[0]
      const entry = cache.get(baseDid)

      if (!entry || Date.now() > entry.expiresAt) {
        const args: [string, DIDResolutionOptions?] = options ? [baseDid, options] : [baseDid]
        const promise = innerResolver.resolve(...args).catch(err => {
          cache.delete(baseDid)
          throw err
        })

        cache.set(baseDid, { promise, expiresAt: Date.now() + ttlMs })
      }

      return cache.get(baseDid)!.promise
    },
    clear: () => {
      cache.clear()
    },
  }
  return cachedResolver as any as CachedResolver
}
