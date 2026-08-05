import { sha1 } from '@noble/hashes/legacy'
import { sha256, sha384, sha512 } from '@noble/hashes/sha2'

export function hash(algorithm: string, data: string) {
  switch (algorithm.toUpperCase()) {
    case 'SHA384':
      return sha384(data)
    case 'SHA512':
      return sha512(data)
    case 'SHA1':
      return sha1(data)
    default:
      throw new Error(`Hash: '${algorithm}' is not supported.`)
  }
}
