import { P256PublicJwk, P384PublicJwk, P521PublicJwk, PublicJwk } from '../modules'
import { VERIFICATION_METHOD_TYPE_JSON_WEB_KEY_2020 } from '@credo-ts/core'
import { KeyDidMapping } from './KeyDidMapping'

export const keyDidJsonWebKey: KeyDidMapping<P256PublicJwk | P384PublicJwk | P521PublicJwk> = {
  PublicJwkTypes: [P256PublicJwk, P384PublicJwk, P521PublicJwk],
  supportedVerificationMethodTypes: [VERIFICATION_METHOD_TYPE_JSON_WEB_KEY_2020],
  getVerificationMethods: (did, publicJwk) => [getJsonWebKey2020({ did, publicJwk })],

  getPublicJwkFromVerificationMethod: () => {
    // This is handled on a higher level
    throw new Error('Not supported for key did json web key')
  },
}

type GetJsonWebKey2020Options = {
  did: string

  verificationMethodId?: string
  publicJwk: PublicJwk
}
/**
 * Get a JsonWebKey2020 verification method.
 */
export function getJsonWebKey2020(options: GetJsonWebKey2020Options) {
  const verificationMethodId = options.verificationMethodId ?? `${options.did}#${options.publicJwk.fingerprint}`

  return {
    id: verificationMethodId,
    type: VERIFICATION_METHOD_TYPE_JSON_WEB_KEY_2020,
    controller: options.did,
    publicKeyJwk: options.publicJwk.toJson(),
  }
}
