import { isEd25519VerificationKey2018, isEd25519VerificationKey2020, TypedArrayEncoder, VERIFICATION_METHOD_TYPE_ED25519_VERIFICATION_KEY_2018, VERIFICATION_METHOD_TYPE_ED25519_VERIFICATION_KEY_2020, VERIFICATION_METHOD_TYPE_JSON_WEB_KEY_2020, VERIFICATION_METHOD_TYPE_MULTIKEY, VerificationMethod } from '@credo-ts/core'
import { Ed25519PublicJwk, getJwkHumanDescription, PublicJwk } from '../modules'
import type { KeyDidMapping } from './KeyDidMapping'

export { convertPublicKeyToX25519 } from '@stablelib/ed25519'

export const keyDidEd25519: KeyDidMapping<Ed25519PublicJwk> = {
  PublicJwkTypes: [Ed25519PublicJwk],
  supportedVerificationMethodTypes: [
    VERIFICATION_METHOD_TYPE_ED25519_VERIFICATION_KEY_2018,
    VERIFICATION_METHOD_TYPE_ED25519_VERIFICATION_KEY_2020,
    VERIFICATION_METHOD_TYPE_JSON_WEB_KEY_2020,
    VERIFICATION_METHOD_TYPE_MULTIKEY,
  ],
  getVerificationMethods: (did, publicJwk) => [
    getEd25519VerificationKey2018({ id: `${did}#${publicJwk.fingerprint}`, publicJwk, controller: did }),
  ],

  getPublicJwkFromVerificationMethod: (verificationMethod: VerificationMethod) => {
    if (isEd25519VerificationKey2018(verificationMethod)) {
      return getPublicJwkFromEd25519VerificationKey2018(verificationMethod)
    }

    if (isEd25519VerificationKey2020(verificationMethod)) {
      return getPublicJwkFromEd25519VerificationKey2020(verificationMethod)
    }

    throw new Error(
      `Verification method with type '${verificationMethod.type}' not supported for key type Ed25519`
    )
  },
}
/**
 * Get a Ed25519VerificationKey2018 verification method.
 */
export function getEd25519VerificationKey2018({
  publicJwk,
  id,
  controller,
}: { id: string; publicJwk: PublicJwk<Ed25519PublicJwk>; controller: string }) {
  return new VerificationMethod({
    id,
    type: VERIFICATION_METHOD_TYPE_ED25519_VERIFICATION_KEY_2018,
    controller,
    publicKeyBase58: TypedArrayEncoder.toBase58(publicJwk.publicKey.publicKey),
  })
}

type Ed25519VerificationKey2018 = VerificationMethod & {
  type: typeof VERIFICATION_METHOD_TYPE_ED25519_VERIFICATION_KEY_2018
}
/**
 * Get a public jwk from a Ed25519VerificationKey2018 verification method.
 */
export function getPublicJwkFromEd25519VerificationKey2018(verificationMethod: Ed25519VerificationKey2018) {
  if (!verificationMethod.publicKeyBase58) {
    throw new Error('verification method is missing publicKeyBase58')
  }

  return PublicJwk.fromPublicKey({
    kty: 'OKP',
    crv: 'Ed25519',
    publicKey: TypedArrayEncoder.fromBase58(verificationMethod.publicKeyBase58),
  })
}

type Ed25519VerificationKey2020 = VerificationMethod & {
  type: typeof VERIFICATION_METHOD_TYPE_ED25519_VERIFICATION_KEY_2020
}
/**
 * Get a key from a Ed25519VerificationKey2020 verification method.
 */
export function getPublicJwkFromEd25519VerificationKey2020(verificationMethod: Ed25519VerificationKey2020) {
  if (!verificationMethod.publicKeyMultibase) {
    throw new Error('verification method is missing publicKeyMultibase')
  }

  const publicJwk = PublicJwk.fromFingerprint(verificationMethod.publicKeyMultibase)
  const publicKey = publicJwk.publicKey

  if (publicKey.kty !== 'OKP' || publicKey.crv !== 'Ed25519') {
    throw new Error(
      `Verification method ${verificationMethod.type} is for unexpected ${getJwkHumanDescription(publicJwk.toJson())}.`
    )
  }

  return publicJwk
}
