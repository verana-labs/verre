import { Agent, AgentContext, DidResolverService } from '@credo-ts/core'
import { Resolver } from 'did-resolver'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

import { ECS, loadSchema, resolve, TrustErrorCode, TrustStatus } from '../src'

import {
  didDocumentChatbot,
  fetchMocker,
  mockCredentialSchema,
  mockDidDocument,
  mockOrgVerifiableCredential,
  mockOrgVerifiableCredentialWithoutIssuer,
  mockPermission,
  mockResolverInstance,
  mockServiceVerifiableCredential,
  setupAgent,
} from './__mocks__'

vi.mock('../src/utils/signatureVerifier', () => ({
  verifyLinkedVP: vi.fn().mockResolvedValue(true),
}))

describe('DidValidator', () => {
  let agent: Agent
  let didResolverService: DidResolverService
  let agentContext: AgentContext
  let didResolver: Resolver

  beforeEach(async () => {
    agent = await setupAgent({
      name: 'did service test',
    })
    didResolverService = agent.dependencyManager.resolve(DidResolverService)
    agentContext = agent.dependencyManager.resolve(AgentContext)
    fetchMocker.enable()

    // Creates a resolver registry that integrates DID resolution strategies
    didResolver = new Resolver({
      web: async (did: string) => didResolverService.resolve(agentContext, did),
      key: async (did: string) => didResolverService.resolve(agentContext, did),
      peer: async (did: string) => didResolverService.resolve(agentContext, did),
      jwk: async (did: string) => didResolverService.resolve(agentContext, did),
    })
  })

  afterEach(() => {
    fetchMocker.reset()
    fetchMocker.disable()
    vi.clearAllMocks()
  })

  describe('resolver method', () => {
    it('should fail for a valid web DID without LinkedVerifiablePresentation', async () => {
      // Real case with 'chatbot-demo.dev.2060.io'
      const did = 'did:web:chatbot-demo.dev.2060.io'

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
      expect(result.didDocument).toEqual({ ...didDocumentChatbot })
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
