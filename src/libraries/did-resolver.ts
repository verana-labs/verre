import { createPublicKey, verify } from 'node:crypto'
import { resolveDID } from 'didwebvh-ts'
import { DIDResolutionResult, DIDResolver, Resolver } from 'did-resolver'
import * as didWeb from 'web-did-resolver'

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
])

const ed25519Verifier = {
  async verify(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array
  ): Promise<boolean> {
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
    const result = await resolveDID(did, { verifier: ed25519Verifier })
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