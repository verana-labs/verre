import { sha1 } from '@noble/hashes/legacy'
import { sha256, sha384, sha512 } from '@noble/hashes/sha2'
import { base64 } from '@scure/base'

export function hash(algorithm: string, data: string) {
  switch (algorithm.toUpperCase()) {
    case 'SHA384':
      return sha384(data)
    case 'SHA512':
      return sha512(data)
    // not a credential digest algorithm, Ed25519Signature2018 hashes its canonicalized document with it
    case 'SHA256':
      return sha256(data)
    case 'SHA1':
      return sha1(data)
    default:
      throw new Error(`Hash: '${algorithm}' is not supported.`)
  }
}

/**
 * Computes the Subresource Integrity value of the raw content.
 *
 * @param algorithm - The hash algorithm, as the prefix of an SRI value names it (for example `sha384`).
 * @param rawContent - The exact text that the digest covers.
 * @returns The SRI value, in the `<algorithm>-<base64 hash>` form.
 */
export function computeDigestSRI(algorithm: string, rawContent: string): string {
  return `${algorithm}-${base64.encode(hash(algorithm, rawContent))}`
}
