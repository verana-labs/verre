import type { W3cVerifiableCredential } from '@credo-ts/core'

import { base64 } from '@scure/base'
import _canonicalize from 'canonicalize'

import { TrustErrorCode } from '../types.js'

import { hash } from './crypto.js'
import { TrustError } from './trustError.js'

const canonicalize = ((_canonicalize as any).default ?? _canonicalize) as (
  input: unknown,
) => string | undefined

// CredentialSchema.digest_algorithm names the algorithm the multihash way, `hash` wants the bare name
const DIGEST_ALGORITHMS: Record<string, string> = {
  'sha2-384': 'SHA384',
  'sha2-512': 'SHA512',
  sha256: 'SHA256',
  sha384: 'SHA384',
  sha512: 'SHA512',
}

const SRI_PREFIX: Record<string, string> = { SHA256: 'sha256', SHA384: 'sha384', SHA512: 'sha512' }

/**
 * The [IDX-VT-EVAL-1] credential digest: JCS (RFC 8785) over the credential with `proof` removed
 * and everything else kept, including `id`. This is what an issuer anchors on the ledger, so it is
 * also what a verifier must recompute. Changing the rule should stay a change to this function.
 */
export function computeCredentialDigestJCS(
  credential: W3cVerifiableCredential,
  digestAlgorithm: string,
): string {
  const algorithm = DIGEST_ALGORITHMS[String(digestAlgorithm).toLowerCase()]
  if (!algorithm)
    throw new TrustError(
      TrustErrorCode.NOT_SUPPORTED,
      `Unsupported credential digest algorithm: ${digestAlgorithm}`,
    )

  const { proof: _proof, ...content } = credential as unknown as Record<string, unknown>
  const canonical = canonicalize(content)
  if (!canonical)
    throw new TrustError(TrustErrorCode.INVALID, 'Failed to canonicalize the credential for digesting')

  return `${SRI_PREFIX[algorithm]}-${base64.encode(hash(algorithm, canonical))}`
}
