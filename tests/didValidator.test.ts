import {
  CacheModuleConfig,
  DidRepository,
  DidResolver,
  DidResolverService,
  DidsModuleConfig,
  InMemoryLruCache,
} from '@credo-ts/core'
import { Resolver, ResolverRegistry } from 'did-resolver'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

import { ECS, loadSchema, resolve, TrustErrorCode, TrustStatus } from '../src'

import {
  fetchMocker,
  getAgentContext,
  mockCredentialSchema,
  mockDidDocument,
  mockOrgVerifiableCredential,
  mockOrgVerifiableCredentialWithoutIssuer,
  mockPermission,
  mockResolverInstance,
  mockServiceVerifiableCredential,
} from './__mocks__'

vi.mock('../src/utils/signatureVerifier', () => ({
  verifyLinkedVP: vi.fn().mockResolvedValue(true),
}))

const didResolverMock = {
  allowsCaching: true,
  allowsLocalDidRecord: false,
  supportedMethods: ['key'],
  resolve: vi.fn(),
} as DidResolver

const recordResolverMock = {
  allowsCaching: false,
  allowsLocalDidRecord: true,
  supportedMethods: ['record'],
  resolve: vi.fn(),
} as DidResolver

const didRepositoryMock = {
  getCreatedDids: vi.fn(),
} as unknown as DidRepository

const cache = new InMemoryLruCache({ limit: 10 })
const agentContext = getAgentContext({
  registerInstances: [[CacheModuleConfig, new CacheModuleConfig({ cache })]],
})

/**
 * Creates a resolver registry that integrates multiple DID resolution strategies.
 *
 * This function returns an object mapping DID methods to their respective resolvers.
 * Currently, it supports the `did:credo:` method, which utilizes the `DidResolverService`
 * to resolve DIDs using predefined resolvers.
 *
 * @returns {ResolverRegistry} An object containing resolver methods for specific DID methods.
 */
const getResolver = (): ResolverRegistry => {
  return {
    credo: async (did: string) => {
      const didResolverService = new DidResolverService(
        agentContext.config.logger,
        new DidsModuleConfig({ resolvers: [didResolverMock, recordResolverMock] }),
        didRepositoryMock,
      )
      return await didResolverService.resolve(agentContext, did)
    },
  }
}

describe('DidValidator', () => {
  const didResolver = new Resolver(getResolver())

  beforeEach(() => {
    fetchMocker.enable()
  })

  afterEach(() => {
    fetchMocker.reset()
    fetchMocker.disable()
    vi.clearAllMocks()
  })

  describe('resolver method', () => {
    it('should fail for a valid web DID without LinkedVerifiablePresentation', async () => {
      // Real case with 'chatbot-demo.dev.2060.io'
      const domain = 'chatbot-demo.dev.2060.io'
      const did = `did:web:${domain}`

      // Setup spy methods
      const resolveSpy = vi.spyOn(Resolver.prototype, 'resolve')

      // Execute method under test
      const result = await resolve(did, { trustRegistryUrl: 'http://testTrust.org', didResolver })

      // Testing
      expect(resolveSpy).toHaveBeenCalledTimes(1)
      expect(resolveSpy).toHaveBeenCalledWith(did)
      expect(result.metadata).toEqual(
        expect.objectContaining({ status: TrustStatus.ERROR, errorCode: TrustErrorCode.NOT_FOUND }),
      )
    })

    it('should work correctly when the issuer is equal to "did".', async () => {
      // Init values
      const did = `did:web:example.com`

      // mocked data
      const resolverInstanceSpy = vi
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
      const result = await resolve(did, { trustRegistryUrl: 'http://testTrust.org', didResolver })
      expect(resolverInstanceSpy).toHaveBeenCalledWith('did:web:example.com')
      expect(result).toEqual(
        expect.objectContaining({
          metadata: { status: TrustStatus.RESOLVED },
          ...mockDidDocument,
          verifiableService: {
            type: ECS.SERVICE,
            credentialSubject: mockServiceVerifiableCredential.verifiableCredential[0].credentialSubject,
          },
          issuerCredential: {
            type: ECS.ORG,
            credentialSubject: mockOrgVerifiableCredential.verifiableCredential[0].credentialSubject,
          },
        }),
      )
    })

    it('should work correctly when the issuer is not "did" without params.', async () => {
      // Init values
      const did = `did:web:example.com`

      // mocked data
      const resolverInstanceSpy = vi
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
      const result = await resolve(did, { trustRegistryUrl: 'http://testTrust.org', didResolver })
      expect(resolverInstanceSpy).toHaveBeenCalledWith('did:web:example.com')
      expect(result).toEqual(
        expect.objectContaining({
          metadata: { status: TrustStatus.RESOLVED },
          ...mockDidDocument,
          verifiableService: {
            type: ECS.SERVICE,
            credentialSubject: mockServiceVerifiableCredential.verifiableCredential[0].credentialSubject,
          },
        }),
      )
    })

    it('should work correctly when the issuer is not "did" with different trustRegistryUrl.', async () => {
      // Init values
      const did = `did:web:example.com`

      // mocked data
      const resolverInstanceSpy = vi
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
      const result = await resolve(did, { trustRegistryUrl: 'http://testTrust.com', didResolver })
      expect(resolverInstanceSpy).toHaveBeenCalledWith('did:web:example.com')
      expect(result).toEqual(
        expect.objectContaining({
          metadata: { status: TrustStatus.RESOLVED },
          ...mockDidDocument,
          verifiableService: {
            type: ECS.SERVICE,
            credentialSubject: mockServiceVerifiableCredential.verifiableCredential[0].credentialSubject,
          },
        }),
      )
    })
  })
})
