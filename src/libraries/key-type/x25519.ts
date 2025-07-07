import { VERIFICATION_METHOD_TYPE_X25519_KEY_AGREEMENT_KEY_2019, VERIFICATION_METHOD_TYPE_JSON_WEB_KEY_2020, VERIFICATION_METHOD_TYPE_MULTIKEY, isX25519KeyAgreementKey2019, TypedArrayEncoder, VerificationMethod } from "@credo-ts/core"
import { PublicJwk, X25519PublicJwk } from "../modules"
import { KeyDidMapping } from "./KeyDidMapping"

export const keyDidX25519: KeyDidMapping<X25519PublicJwk> = {
  PublicJwkTypes: [X25519PublicJwk],
  supportedVerificationMethodTypes: [
    VERIFICATION_METHOD_TYPE_X25519_KEY_AGREEMENT_KEY_2019,
    VERIFICATION_METHOD_TYPE_JSON_WEB_KEY_2020,
    VERIFICATION_METHOD_TYPE_MULTIKEY,
  ],
  getVerificationMethods: (did, publicJwk) => [
    getX25519KeyAgreementKey2019({ id: `${did}#${publicJwk.fingerprint}`, publicJwk, controller: did }),
  ],

  getPublicJwkFromVerificationMethod: (verificationMethod: VerificationMethod) => {
    if (isX25519KeyAgreementKey2019(verificationMethod)) {
      return getPublicJwkFrommX25519KeyAgreementKey2019(verificationMethod)
    }

    throw new Error(`Verification method with type '${verificationMethod.type}' not supported for key type X25519`)
  },
}

/**
 * Get a X25519KeyAgreementKey2019 verification method.
 */
export function getX25519KeyAgreementKey2019({
  publicJwk,
  id,
  controller,
}: { id: string; publicJwk: PublicJwk<X25519PublicJwk>; controller: string }) {
  return new VerificationMethod({
    id,
    type: VERIFICATION_METHOD_TYPE_X25519_KEY_AGREEMENT_KEY_2019,
    controller,
    publicKeyBase58: TypedArrayEncoder.toBase58(publicJwk.publicKey.publicKey),
  })
}

type X25519KeyAgreementKey2019 = VerificationMethod & {
  type: typeof VERIFICATION_METHOD_TYPE_X25519_KEY_AGREEMENT_KEY_2019
}
/**
 * Get a key from a X25519KeyAgreementKey2019 verification method.
 */
export function getPublicJwkFrommX25519KeyAgreementKey2019(verificationMethod: X25519KeyAgreementKey2019) {
  if (!verificationMethod.publicKeyBase58) {
    throw new Error('verification method is missing publicKeyBase58')
  }

  return PublicJwk.fromPublicKey({
    kty: 'OKP',
    crv: 'X25519',
    publicKey: TypedArrayEncoder.fromBase58(verificationMethod.publicKeyBase58),
  })
}
