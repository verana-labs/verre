import { Resolver } from 'did-resolver'

import { ECS, loadSchema, resolve } from '../src'

import {
  fetchMocker,
  mockCredentialSchema,
  mockIssuerDidDoc,
  mockNotIssuerDidDoc,
  mockOrgVerifiableCredential,
  mockOrgVerifiableCredentialWithoutIssuer,
  mockPermission,
  mockResolverInstance,
  mockServiceVerifiableCredential,
} from './__mocks__'

jest.mock('../src/utils/signatureVerifier', () => ({
  verifyLinkedVP: jest.fn().mockResolvedValue(true),
}))

describe('DidValidator', () => {
  beforeEach(() => {
    fetchMocker.enable()
  })

  afterEach(() => {
    fetchMocker.reset()
    fetchMocker.disable()
    jest.clearAllMocks()
  })

  describe('resolver method', () => {
    it('should fail for a valid web DID without LinkedVerifiablePresentation', async () => {
      // Real case with 'chatbot-demo.dev.2060.io'
      const domain = 'chatbot-demo.dev.2060.io'
      const did = `did:web:${domain}`

      // Setup spy methods
      const resolveSpy = jest.spyOn(Resolver.prototype, 'resolve')

      // Execute method under test
      const result = await resolve(did)

      // Testing
      expect(resolveSpy).toHaveBeenCalledTimes(1)
      expect(resolveSpy).toHaveBeenCalledWith(did)
      expect(result).toEqual(expect.objectContaining({ result: false }))
    })

    it('should work correctly when the issuer is equal to "did".', async () => {
      // Init values
      const did = `did:web:example.com`

      // mocked data
      const resolverInstanceSpy = jest
        .spyOn(Resolver.prototype, 'resolve')
        .mockResolvedValue({ ...mockResolverInstance })
      fetchMocker.setMockResponses({
        'https://example.com/vp-ser': { ok: true, status: 200, data: mockServiceVerifiableCredential },
        'https://ecs-trust-registry/service-credential-schema-credential.json': {
          ok: true,
          status: 200,
          data: { json_schema: JSON.stringify(loadSchema(ECS.SERVICE)) },
        },
        'https://example.com/vp-org': { ok: true, status: 200, data: mockOrgVerifiableCredential },
        'https://ecs-trust-registry/organization-credential-schema-credential.json': {
          ok: true,
          status: 200,
          data: { json_schema: JSON.stringify(loadSchema(ECS.ORG)) },
        },
        'https://example.com/trust-registry': { ok: true, status: 200, data: {} },
      })

      // Execute method under test
      const result = await resolve(did)
      expect(resolverInstanceSpy).toHaveBeenCalledWith('did:web:example.com')
      expect(result).toEqual(expect.objectContaining({ result: true, ...mockIssuerDidDoc }))
    })

    it('should work correctly when the issuer is not "did" without params.', async () => {
      // Init values
      const did = `did:web:example.com`

      // mocked data
      const resolverInstanceSpy = jest
        .spyOn(Resolver.prototype, 'resolve')
        .mockResolvedValue({ ...mockResolverInstance })
      fetchMocker.setMockResponses({
        'https://example.com/vp-ser': { ok: true, status: 200, data: mockServiceVerifiableCredential },
        'https://ecs-trust-registry/service-credential-schema-credential.json': {
          ok: true,
          status: 200,
          data: { json_schema: JSON.stringify(loadSchema(ECS.SERVICE)) },
        },
        'https://example.com/vp-org': {
          ok: true,
          status: 200,
          data: mockOrgVerifiableCredentialWithoutIssuer,
        },
        'https://ecs-trust-registry/organization-credential-schema-credential.json': {
          ok: true,
          status: 200,
          data: { json_schema: JSON.stringify(loadSchema(ECS.ORG)) },
        },
        'https://example.com/trust-registry': { ok: true, status: 200, data: {} },
        'http://testTrust.org/prem/v1/get': { ok: true, status: 200, data: mockPermission },
        'http://testTrust.org/cs/v1/get': { ok: true, status: 200, data: mockCredentialSchema },
      })

      // Execute method under test
      const result = await resolve(did)
      expect(resolverInstanceSpy).toHaveBeenCalledWith('did:web:example.com')
      expect(result).toEqual(expect.objectContaining({ result: true, ...mockNotIssuerDidDoc }))
    })

    it('should work correctly when the issuer is not "did" with different trustRegistryUrl.', async () => {
      // Init values
      const did = `did:web:example.com`

      // mocked data
      const resolverInstanceSpy = jest
        .spyOn(Resolver.prototype, 'resolve')
        .mockResolvedValue({ ...mockResolverInstance })
      fetchMocker.setMockResponses({
        'https://example.com/vp-ser': { ok: true, status: 200, data: mockServiceVerifiableCredential },
        'https://ecs-trust-registry/service-credential-schema-credential.json': {
          ok: true,
          status: 200,
          data: { json_schema: JSON.stringify(loadSchema(ECS.SERVICE)) },
        },
        'https://example.com/vp-org': {
          ok: true,
          status: 200,
          data: mockOrgVerifiableCredentialWithoutIssuer,
        },
        'https://ecs-trust-registry/organization-credential-schema-credential.json': {
          ok: true,
          status: 200,
          data: { json_schema: JSON.stringify(loadSchema(ECS.ORG)) },
        },
        'https://example.com/trust-registry': { ok: true, status: 200, data: {} },
        'http://testTrust.com/prem/v1/get': { ok: true, status: 200, data: mockPermission },
        'http://testTrust.com/cs/v1/get': { ok: true, status: 200, data: mockCredentialSchema },
      })

      // Execute method under test
      const result = await resolve(did, { trustRegistryUrl: 'http://testTrust.com' })
      expect(resolverInstanceSpy).toHaveBeenCalledWith('did:web:example.com')
      expect(result).toEqual(expect.objectContaining({ result: true, ...mockNotIssuerDidDoc }))
    })
  })
})
