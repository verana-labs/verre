import { DIDResolutionResult, DIDResolver, Resolver } from 'did-resolver'
import { resolveDID as resolveWebVh } from 'didwebvh-ts'
import { createPublicKey, verify } from 'node:crypto'
import * as didWeb from 'web-did-resolver'

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
])

const ed25519Verifier = {
  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKey)]),
      format: 'der',
      type: 'spki',
    })
    return verify(null, message, key, signature)
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

export const resolverInstance = new Resolver({
  ...didWeb.getResolver(),
  webvh: webVhDidResolver,
})

/**
 * Resolves a DID (did:web or did:webvh) and returns the DIDResolutionResult.
 * Throws if the DID method is not supported or resolution fails.
 */
export async function resolveDID(did: string): Promise<DIDResolutionResult> {
  const supportedMethods = ['web', 'webvh']
  const method = did.split(':')[1]

  if (!method || !supportedMethods.includes(method)) {
    return {
      didResolutionMetadata: {
        error: 'methodNotSupported',
        message: `Method "${method}" is not supported. Supported methods: ${supportedMethods.join(', ')}`,
      },
      didDocument: null,
      didDocumentMetadata: {},
    }
  }

  const result = await resolverInstance.resolve(did)

  if (result.didResolutionMetadata?.error) {
    throw new Error(
      `Failed to resolve DID "${did}": ${result.didResolutionMetadata.error}` +
        (result.didResolutionMetadata.message ? ` — ${result.didResolutionMetadata.message}` : ''),
    )
  }

  return result
}
