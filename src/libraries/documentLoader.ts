import jsonld from '@digitalcredentials/jsonld'
import { Resolver } from 'did-resolver'

import { DEFAULT_CONTEXTS } from './defaultContexts'
import { resolverInstance } from './did-resolver'
import { getNativeDocumentLoader } from './nativeDocumentLoader'

export function createDocumentLoader(customResolver?: Resolver) {
  const didResolver = customResolver || resolverInstance

  async function loader(url: string): Promise<{
    contextUrl: string | null
    documentUrl: string
    document: Record<string, unknown>
  }> {
    if (url in DEFAULT_CONTEXTS) {
      return {
        contextUrl: null,
        documentUrl: url,
        document: DEFAULT_CONTEXTS[url as keyof typeof DEFAULT_CONTEXTS],
      }
    }

    const withoutFragment = url.split('#')[0]
    if (withoutFragment in DEFAULT_CONTEXTS) {
      return {
        contextUrl: null,
        documentUrl: url,
        document: DEFAULT_CONTEXTS[withoutFragment as keyof typeof DEFAULT_CONTEXTS],
      }
    }

    if (url.startsWith('did:')) {
      const result = await didResolver.resolve(url)

      if (result.didResolutionMetadata?.error || !result.didDocument) {
        throw new Error(`Unable to resolve DID: ${url}. Error: ${result.didResolutionMetadata?.error}`)
      }

      const framed = await jsonld.frame(
        result.didDocument,
        {
          '@context': result.didDocument['@context'] || 'https://www.w3.org/ns/did/v1',
          '@embed': '@never',
          id: url,
        },
        { documentLoader: loader as any },
      )

      return {
        contextUrl: null,
        documentUrl: url,
        document: framed as Record<string, unknown>,
      }
    }

    const platformLoader = await getNativeDocumentLoader()
    const nativeLoader = platformLoader.apply(jsonld, [])

    return await nativeLoader(url)
  }

  return loader.bind(loader)
}
