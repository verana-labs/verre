import { Resolver } from 'did-resolver'
import { describe, expect, it } from 'vitest'

import { IVerreLogger } from '../../src/types'
import { verifySignature } from '../../src/utils/verifier'
import { integrationDidDoc, linkedVpService } from '../__mocks__'

// Linked Data Proofs (Ed25519Signature2018/2020) are held to the same proof purpose rules as
// Data Integrity proofs: the purpose must fit the document, and the DID document must list the
// verification method under that purpose.
type Document = Parameters<typeof verifySignature>[0]
const silentLogger: IVerreLogger = { debug() {}, info() {}, warn() {}, error() {} }
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value))

const resolverFor = (didDocument: unknown) =>
  ({
    resolve: async () => ({ didResolutionMetadata: {}, didDocumentMetadata: {}, didDocument }),
  }) as unknown as Resolver

const verificationMethodId = linkedVpService.proof.verificationMethod as string

describe('Linked Data Proof purpose validation', () => {
  it('verifies the legacy presentation when the key is listed for its purpose', async () => {
    const { result, error } = await verifySignature(
      linkedVpService as Document,
      resolverFor(integrationDidDoc),
      silentLogger,
    )
    expect(error).toBeUndefined()
    expect(result).toBe(true)
  })

  it('rejects a presentation whose key is not listed for its proof purpose', async () => {
    const { result, error } = await verifySignature(
      linkedVpService as Document,
      resolverFor({ ...integrationDidDoc, assertionMethod: [] }),
      silentLogger,
    )
    expect(result).toBe(false)
    expect(error).toBe(
      `Verification method ${verificationMethodId} is not authorized for proof purpose 'assertionMethod'`,
    )
  })

  it('rejects a proof purpose the document kind does not accept', async () => {
    const credential = clone(linkedVpService.verifiableCredential[0])
    credential.proof.proofPurpose = 'authentication'
    const { result, error } = await verifySignature(
      credential as Document,
      resolverFor(integrationDidDoc),
      silentLogger,
    )
    expect(result).toBe(false)
    expect(error).toBe("Unexpected proofPurpose 'authentication', expected one of: assertionMethod")
  })

  it('rejects a proof without a purpose', async () => {
    const credential = clone(linkedVpService.verifiableCredential[0])
    delete (credential.proof as { proofPurpose?: string }).proofPurpose
    const { result, error } = await verifySignature(
      credential as Document,
      resolverFor(integrationDidDoc),
      silentLogger,
    )
    expect(result).toBe(false)
    expect(error).toBe('Missing proofPurpose in proof')
  })
})
