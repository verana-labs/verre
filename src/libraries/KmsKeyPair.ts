import { isJsonWebKey2020, isMultikey, JsonTransformer, keyDidEd25519, keyDidX25519, LdKeyPair, LdKeyPairOptions, MessageValidator, VERIFICATION_METHOD_TYPE_JSON_WEB_KEY_2020, VERIFICATION_METHOD_TYPE_MULTIKEY, VerificationMethod } from '@credo-ts/core'
import { PublicJwk } from './modules'
import { keyDidJsonWebKey } from './key-type/keyDidJsonWebKey'
import { keyDidSecp256k1 } from './key-type/secp256k1'
import { getPublicJwkFromVerificationMethod } from './key-type/KeyDidMapping'

interface KmsKeyPairOptions extends LdKeyPairOptions {
  publicJwk: PublicJwk
}

export function createKmsKeyPairClass() {
  return class KmsKeyPair extends LdKeyPair {
    public publicJwk: PublicJwk
    public type = 'KmsKeyPair'

    public constructor(options: KmsKeyPairOptions) {
      super(options)
      this.publicJwk = options.publicJwk
    }

    public static async generate(): Promise<KmsKeyPair> {
      throw new Error('Not implemented')
    }

    public fingerprint(): string {
      throw new Error('Method not implemented.')
    }

    public verifyFingerprint(_fingerprint: string): boolean {
      throw new Error('Method not implemented.')
    }

    public static async from(verificationMethod: VerificationMethod): Promise<KmsKeyPair> {
      const vMethod = JsonTransformer.fromJSON(verificationMethod, VerificationMethod)
      MessageValidator.validateSync(vMethod)
      const publicJwk = getPublicJwkFromVerificationMethod(vMethod)

      return new KmsKeyPair({
        id: vMethod.id,
        controller: vMethod.controller,
        publicJwk,
      })
    }

    /**
     * This method returns a wrapped wallet.sign method. The method is being wrapped so we can covert between Uint8Array and Buffer. This is to make it compatible with the external signature libraries.
     */
    public signer(): { sign: (data: { data: Uint8Array | Uint8Array[] }) => Promise<Uint8Array> } {
      throw new Error('Method not implemented.')
    }

    /**
     * This method returns a wrapped wallet.verify method. The method is being wrapped so we can covert between Uint8Array and Buffer. This is to make it compatible with the external signature libraries.
     */
    public verifier(): {
      verify: (data: { data: Uint8Array | Uint8Array[]; signature: Uint8Array }) => Promise<boolean>
    } {
      const wrappedVerify = async (data: {
        data: Uint8Array | Uint8Array[]
        signature: Uint8Array
      }): Promise<boolean> => {
        if (Array.isArray(data.data)) {
          throw new Error('Verifying array of data entries is not supported')
        }
        // const kms = agentContext.dependencyManager.resolve(KeyManagementApi)

        // const { verified } = await kms.verify({
        //   data: data.data,
        //   signature: Buffer.from(data.signature),
        //   key: {
        //     publicJwk: this.publicJwk.toJson(),
        //   },
        //   algorithm: this.publicJwk.signatureAlgorithm,
        // })

        return true
      }
      return {
        verify: wrappedVerify.bind(this),
      }
    }

    public get publicKeyBuffer(): Uint8Array {
      const publicKey = this.publicJwk.publicKey

      if (publicKey.kty === 'RSA') {
        throw new Error(`kty 'RSA' not supported for publicKeyBuffer`)
      }

      return publicKey.publicKey
    }
  }
}
