import { isEcdsaSecp256k1VerificationKey2019, TypedArrayEncoder, VERIFICATION_METHOD_TYPE_ECDSA_SECP256K1_VERIFICATION_KEY_2019, VERIFICATION_METHOD_TYPE_JSON_WEB_KEY_2020, VERIFICATION_METHOD_TYPE_MULTIKEY, VerificationMethod } from '@credo-ts/core'
import { PublicJwk, Secp256k1PublicJwk } from '../modules'
import type { KeyDidMapping } from './KeyDidMapping'
import { getJsonWebKey2020 } from './keyDidJsonWebKey'

export const keyDidSecp256k1: KeyDidMapping<Secp256k1PublicJwk> = {
  PublicJwkTypes: [Secp256k1PublicJwk],
  supportedVerificationMethodTypes: [
    VERIFICATION_METHOD_TYPE_ECDSA_SECP256K1_VERIFICATION_KEY_2019,
    VERIFICATION_METHOD_TYPE_JSON_WEB_KEY_2020,
    VERIFICATION_METHOD_TYPE_MULTIKEY,
  ],
  getVerificationMethods: (did, publicJwk) => [getJsonWebKey2020({ did, publicJwk })],
  getPublicJwkFromVerificationMethod: (verificationMethod: VerificationMethod) => {
    if (isEcdsaSecp256k1VerificationKey2019(verificationMethod)) {
      return getPublicJwkFromEcdsaSecp256k1VerificationKey2019(verificationMethod)
    }

    throw new Error(
      `Verification method with type '${verificationMethod.type}' not supported for key type Secp256K1`
    )
  },
}

type EcdsaSecp256k1VerificationKey2019 = VerificationMethod & {
  type: typeof VERIFICATION_METHOD_TYPE_ECDSA_SECP256K1_VERIFICATION_KEY_2019
}

/**
 * Get a public jwk from a EcdsaSecp256k1VerificationKey2019 verification method.
 */
export function getPublicJwkFromEcdsaSecp256k1VerificationKey2019(
  verificationMethod: EcdsaSecp256k1VerificationKey2019
) {
  if (!verificationMethod.publicKeyBase58) {
    throw new Error('verification method is missing publicKeyBase58')
  }

  return PublicJwk.fromPublicKey({
    kty: 'EC',
    crv: 'secp256k1',
    publicKey: TypedArrayEncoder.fromBase58(verificationMethod.publicKeyBase58),
  })
}
