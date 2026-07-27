import { Resolver } from 'did-resolver'
import { describe, expect, it } from 'vitest'

import { IVerreLogger } from '../../src/types'
import { verifySignature } from '../../src/utils/verifier'
import { integrationDidDoc, linkedVpService } from '../__mocks__'

const resolver = {
  resolve: async () => ({
    didResolutionMetadata: {},
    didDocumentMetadata: {},
    didDocument: integrationDidDoc,
  }),
} as unknown as Resolver

const silentLogger: IVerreLogger = { debug() {}, info() {}, warn() {}, error() {} }

const stripJwsPadding = (value: unknown): unknown =>
  JSON.parse(JSON.stringify(value), (key, v) =>
    key === 'jws' && typeof v === 'string' ? v.replace(/=+$/u, '') : v,
  )

describe('JWS base64url padding tolerance', () => {
  it('verifies unpadded JWS signatures (RFC 7515)', async () => {
    const vp = stripJwsPadding(linkedVpService) as Parameters<typeof verifySignature>[0]
    const { result, error } = await verifySignature(vp, resolver, silentLogger)
    expect(error).toBeUndefined()
    expect(result).toBe(true)
  })

  it('still verifies legacy padded JWS signatures', async () => {
    const { result, error } = await verifySignature(
      linkedVpService as Parameters<typeof verifySignature>[0],
      resolver,
      silentLogger,
    )
    expect(error).toBeUndefined()
    expect(result).toBe(true)
  })
})
