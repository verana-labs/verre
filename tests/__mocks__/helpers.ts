// Remove public keys from the DID document for testing purposes,
// as they aren't the same across different did documents over real use cases.
export function stripPublicKeys(didDocument: any) {
  return {
    ...didDocument,
    verificationMethod: didDocument.verificationMethod.map(({ publicKeyBase58, ...rest }: any) => rest),
  }
}
