import { isJsonWebKey2020, isMultikey, VERIFICATION_METHOD_TYPE_JSON_WEB_KEY_2020, VERIFICATION_METHOD_TYPE_MULTIKEY, VerificationMethod } from '@credo-ts/core'
import { PublicJwk, SupportedPublicJwkClass } from '../modules/kms/jwk/PublicJwk'
import { keyDidJsonWebKey } from './keyDidJsonWebKey'
import { Constructor } from '../../utils/mixins'
import { keyDidSecp256k1 } from './secp256k1'
import { keyDidEd25519 } from './ed25519'
import { keyDidX25519 } from './x25519'

export interface KeyDidMapping<
  PublicJwkType extends InstanceType<SupportedPublicJwkClass> = InstanceType<SupportedPublicJwkClass>,
> {
  PublicJwkTypes: Array<Constructor<PublicJwkType>>
  getVerificationMethods: (did: string, publicJwk: PublicJwk<PublicJwkType>) => VerificationMethod[]
  getPublicJwkFromVerificationMethod(verificationMethod: VerificationMethod): PublicJwk
  supportedVerificationMethodTypes: string[]
}

const supportedKeyDids = [keyDidEd25519, keyDidX25519, keyDidJsonWebKey, keyDidSecp256k1]

// TODO: at some point we should update all usages to Jwk / Multikey methods
// so we don't need key type specific verification methods anymore
export function getVerificationMethodsForPublicJwk(publicJwk: PublicJwk, did: string) {
  const { getVerificationMethods } = getKeyDidMappingByPublicJwk(publicJwk)

  return getVerificationMethods(did, publicJwk)
}

export function getSupportedVerificationMethodTypesForPublicJwk(
  publicJwk: PublicJwk | SupportedPublicJwkClass
): string[] {
  const { supportedVerificationMethodTypes } = getKeyDidMappingByPublicJwk(publicJwk)

  return supportedVerificationMethodTypes
}

export function getPublicJwkFromVerificationMethod(verificationMethod: VerificationMethod): PublicJwk {
  // This is a special verification method, as it supports basically all key types.
  if (isJsonWebKey2020(verificationMethod)) {
    return getPublicJwkFromJsonWebKey2020(verificationMethod)
  }

  if (isMultikey(verificationMethod)) {
    return getPublicJwkFromMultikey(verificationMethod)
  }

  const keyDid = supportedKeyDids.find((keyDid) =>
    keyDid.supportedVerificationMethodTypes.includes(verificationMethod.type)
  )
  if (!keyDid) {
    throw new Error(`Unsupported key did from verification method type '${verificationMethod.type}'`)
  }

  return keyDid.getPublicJwkFromVerificationMethod(verificationMethod)
}

function getKeyDidMappingByPublicJwk(jwk: PublicJwk | SupportedPublicJwkClass): KeyDidMapping {
  const jwkTypeClass = jwk instanceof PublicJwk ? jwk.JwkClass : jwk

  const keyDid = supportedKeyDids.find((supportedKeyDid) =>
    // biome-ignore lint/suspicious/noExplicitAny: <explanation>
    supportedKeyDid.PublicJwkTypes.includes(jwkTypeClass as any)
  )

  if (!keyDid) {
    throw new Error(
      `Unsupported did mapping for jwk '${jwk instanceof PublicJwk ? jwk.jwkTypehumanDescription : jwk.name}'`
    )
  }

  return keyDid as KeyDidMapping
}

export function getPublicJwkFromMultikey(verificationMethod: VerificationMethod & { type: 'Multikey' }) {
  if (!verificationMethod.publicKeyMultibase) {
    throw new Error(
      `Missing publicKeyMultibase on verification method with type ${VERIFICATION_METHOD_TYPE_MULTIKEY}`
    )
  }

  return PublicJwk.fromFingerprint(verificationMethod.publicKeyMultibase)
}

/**
 * Get a key from a JsonWebKey2020 verification method.
 */
export function getPublicJwkFromJsonWebKey2020(verificationMethod: VerificationMethod & { type: 'JsonWebKey2020' }) {
  if (!verificationMethod.publicKeyJwk) {
    throw new Error(
      `Missing publicKeyJwk on verification method with type ${VERIFICATION_METHOD_TYPE_JSON_WEB_KEY_2020}`
    )
  }

  return PublicJwk.fromUnknown(verificationMethod.publicKeyJwk)
}

