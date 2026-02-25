import { ed25519 } from '@noble/curves/ed25519.js'
import { DIDResolutionOptions, DIDResolutionResult, DIDResolver, Resolver } from 'did-resolver'
import { resolveDID as resolveWebVh } from 'didwebvh-ts'
import * as didWeb from 'web-did-resolver'

const ed25519Verifier = {
  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    return ed25519.verify(signature, message, publicKey)
  },
}

const webVhDidResolver: DIDResolver = async (did: string): Promise<DIDResolutionResult> => {
  try {
    const result = await resolveWebVh(did, { verifier: ed25519Verifier })
    if (result.meta?.error || !result.doc) {
      return {
        didResolutionMetadata: { error: 'notFound' },
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
    return {
      didResolutionMetadata: { error: 'internalError', message },
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
export function createCachedResolver(innerResolver: Resolver): CachedResolver {
  const cache = new Map<string, Promise<DIDResolutionResult>>()

  const cachedResolver = {
    ...innerResolver,
    resolve: async (didUrl: string, options?: DIDResolutionOptions): Promise<DIDResolutionResult> => {
      const baseDid = didUrl.split(/[#?]/)[0]

      if (!cache.has(baseDid)) {
        const args: [string, DIDResolutionOptions?] = options ? [baseDid, options] : [baseDid]
        const promise = innerResolver.resolve(...args).catch(err => {
          cache.delete(baseDid)
          throw err
        })

        cache.set(baseDid, promise)
      }

      return cache.get(baseDid)!
    },
    clear: () => {
      cache.clear()
    },
  }
  return cachedResolver as any as CachedResolver
}
