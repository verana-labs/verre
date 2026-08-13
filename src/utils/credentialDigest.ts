import { base64 } from '@scure/base'
import _canonicalize from 'canonicalize'

import { TrustErrorCode } from '../types.js'

import { hash } from './crypto.js'
import { TrustError } from './trustError.js'

const canonicalize = ((_canonicalize as any).default ?? _canonicalize) as (
  input: unknown,
) => string | undefined

const DIGEST_ALGORITHMS: Record<string, string> = {
  sha384: 'SHA384',
  sha512: 'SHA512',
}

/**
 * JCS (RFC 8785) over the credential as issued, in its entirety: no member is removed, `id` and
 * `proof` are both included, then base64 with padding and no algorithm prefix. The algorithm comes
 * from the schema, not the value. See the Verifiable Trust spec, Computing `digestJCS`.
 */
export function computeCredentialDigestJCS(
  credential: object,
  digestAlgorithm: string,
): string {
  const algorithm = DIGEST_ALGORITHMS[String(digestAlgorithm).toLowerCase()]
  if (!algorithm)
    throw new TrustError(
      TrustErrorCode.NOT_SUPPORTED,
      `Unsupported credential digest algorithm: ${digestAlgorithm}`,
    )

  const canonical = canonicalize(credential)
  if (!canonical)
    throw new TrustError(TrustErrorCode.INVALID, 'Failed to canonicalize the credential for digesting')

  return base64.encode(hash(algorithm, canonical))
}
