import { Agent, AgentContext, DidResolverService } from '@credo-ts/core'
import { Resolver } from 'did-resolver'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

import { ECS, resolve, TrustErrorCode } from '../src'
import * as signatureVerifier from '../src/utils/verifier'

import {
  mockDidDocumentChatbot,
  didExtIssuer,
  didSelfIssued,
  fetchMocker,
  mockCredentialSchemaOrg,
  mockCredentialSchemaSer,
  mockDidDocumentSelfIssued,
  mockDidDocumentSelfIssuedExtIssuer,
  mockResolverExtIssuer,
  mockOrgSchema,
  mockOrgSchemaWithoutIssuer,
  mockOrgVc,
  mockOrgVcWithoutIssuer,
  mockPermission,
  mockResolverSelfIssued,
  mockServiceSchemaExtIssuer,
  mockServiceExtIssuerVc,
  mockServiceSchemaSelfIssued,
  mockServiceVcSelfIssued,
  setupAgent,
} from './__mocks__'

const mockResolversByDid: Record<string, any> = {
  [didExtIssuer]: { ...mockResolverExtIssuer },
  [didSelfIssued]: { ...mockResolverSelfIssued },
}

describe('DidValidator', () => {
  let agent: Agent
  let didResolverService: DidResolverService
  let agentContext: AgentContext
  let didResolver: Resolver

  beforeEach(async () => {
    // Create an agent for Credo-TS using the DID resolver
    agent = await setupAgent({
      name: 'DID Service Test',
    })
    didResolverService = agent.dependencyManager.resolve(DidResolverService)
    agentContext = agent.dependencyManager.resolve(AgentContext)

    // Mock verifySignature function since there is no credential signature
    vi.spyOn(signatureVerifier, 'verifySignature').mockResolvedValue(true)

    // Mock global fetch
    fetchMocker.enable()

    // Create a resolver registry that integrates DID resolution strategies (using the Credo-TS dependency)
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
      const did = 'did:web:dm.chatbot.demos.dev.2060.io'

      // Setup spy methods
      const resolveSpy = vi.spyOn(Resolver.prototype, 'resolve')

      // Execute method under test
      const result = await resolve(did, {
        trustRegistryUrl: 'http://testTrust.org',
        didResolver,
        agentContext,
      })

      // Testing
      expect(resolveSpy).toHaveBeenCalledTimes(1)
      expect(resolveSpy).toHaveBeenCalledWith(did)
      expect(result.verified).toEqual(false)
      expect(result.metadata).toEqual(expect.objectContaining({ errorCode: TrustErrorCode.NOT_FOUND }))
      expect(result.didDocument).toEqual({ ...mockDidDocumentChatbot })
    })

    it('should work correctly when the issuer is equal to "did".', async () => {
      // mocked data
      const resolverInstanceSpy = vi
        .spyOn(Resolver.prototype, 'resolve')
        .mockImplementation(async (did: string) => {
          return mockResolversByDid[did]
        })
      fetchMocker.setMockResponses({
        'https://example.com/vp-ser-self-issued': { ok: true, status: 200, data: mockServiceVcSelfIssued },
        'https://example.com/vp-org': { ok: true, status: 200, data: mockOrgVc },
        'https://ecs-trust-registry/service-credential-schema-credential.json': {
          ok: true,
          status: 200,
          data: mockServiceSchemaSelfIssued,
        },
        'https://ecs-trust-registry/org-credential-schema-credential.json': {
          ok: true,
          status: 200,
          data: mockOrgSchema,
        },
        'https://vpr-hostname/vpr/v1/cs/js/12345671': {
          ok: true,
          status: 200,
          data: mockCredentialSchemaOrg,
        },
        'https://vpr-hostname/vpr/v1/cs/js/12345678': {
          ok: true,
          status: 200,
          data: mockCredentialSchemaSer,
        },
        'https://example.com/trust-registry': { ok: true, status: 200, data: {} },
        'http://testTrust.org/perm/v1/find_with_did?did=did%3Aweb%3Aservice.self-issued.example.com': {
          ok: true,
          status: 200,
          data: mockPermission,
        },
      })

      // Execute method under test
      const result = await resolve(didSelfIssued, {
        trustRegistryUrl: 'http://testTrust.org',
        didResolver,
        agentContext,
      })
      expect(resolverInstanceSpy).toHaveBeenCalledWith(didSelfIssued)
      expect(resolverInstanceSpy).toHaveBeenCalledTimes(1)
      expect(result).toEqual(
        expect.objectContaining({
          verified: true,
          ...mockDidDocumentSelfIssued,
          service: {
            type: ECS.SERVICE,
            issuer: didSelfIssued,
            credentialSubject: mockServiceVcSelfIssued.verifiableCredential[0].credentialSubject,
          },
          serviceProvider: {
            type: ECS.ORG,
            issuer: didSelfIssued,
            credentialSubject: mockOrgVc.verifiableCredential[0].credentialSubject,
          },
        }),
      )
    })

    it('should work correctly when the issuer is not "did" without params.', async () => {
      // mocked data
      const resolverInstanceSpy = vi
        .spyOn(Resolver.prototype, 'resolve')
        .mockImplementation(async (did: string) => {
          return mockResolversByDid[did]
        })
      fetchMocker.setMockResponses({
        'https://example.com/vp-ser-self-issued': { ok: true, status: 200, data: mockServiceVcSelfIssued },
        'https://example.com/vp-ser-ext-issued': {
          ok: true,
          status: 200,
          data: mockServiceExtIssuerVc,
        },
        'https://example.com/vp-org': {
          ok: true,
          status: 200,
          data: mockOrgVcWithoutIssuer,
        },
        'https://ecs-trust-registry/service-credential-schema-credential.json': {
          ok: true,
          status: 200,
          data: mockServiceSchemaSelfIssued,
        },
        'https://ecs-trust-registry/service-ext-issuer-credential-schema-credential.json': {
          ok: true,
          status: 200,
          data: mockServiceSchemaExtIssuer,
        },
        'https://ecs-trust-registry/org-credential-schema-credential.json': {
          ok: true,
          status: 200,
          data: mockOrgSchemaWithoutIssuer,
        },
        'https://vpr-hostname/vpr/v1/cs/js/12345673': {
          ok: true,
          status: 200,
          data: mockCredentialSchemaOrg,
        },
        'https://vpr-hostname/vpr/v1/cs/js/12345678': {
          ok: true,
          status: 200,
          data: mockCredentialSchemaSer,
        },
        'https://example.com/trust-registry': { ok: true, status: 200, data: {} },
        'http://testTrust.org/perm/v1/find_with_did?did=did%3Aweb%3Aservice.self-issued.example.com': {
          ok: true,
          status: 200,
          data: mockPermission,
        },
        'http://testTrust.org/cs/v1/get': { ok: true, status: 200, data: mockCredentialSchemaOrg },
      })

      // Execute method under test
      const result = await resolve(didExtIssuer, { trustRegistryUrl: 'http://testTrust.org', agentContext })
      expect(resolverInstanceSpy).toHaveBeenCalledWith(didExtIssuer)
      expect(resolverInstanceSpy).toHaveBeenCalledWith(didSelfIssued)
      expect(resolverInstanceSpy).toHaveBeenCalledTimes(2)
      expect(result).toEqual(
        expect.objectContaining({
          verified: true,
          ...mockDidDocumentSelfIssuedExtIssuer,
          service: {
            type: ECS.SERVICE,
            issuer: didSelfIssued,
            credentialSubject: mockServiceExtIssuerVc.verifiableCredential[0].credentialSubject,
          },
          serviceProvider: {
            type: ECS.ORG,
            issuer: didSelfIssued,
            credentialSubject: mockOrgVcWithoutIssuer.verifiableCredential[0].credentialSubject,
          },
        }),
      )
    })

    it('should work correctly when the issuer is not "did" with different trustRegistryUrl.', async () => {
      // mocked data
      const resolverInstanceSpy = vi
        .spyOn(Resolver.prototype, 'resolve')
        .mockImplementation(async (did: string) => {
          return mockResolversByDid[did]
        })
      fetchMocker.setMockResponses({
        'https://example.com/vp-ser-self-issued': { ok: true, status: 200, data: mockServiceVcSelfIssued },
        'https://example.com/vp-ser-ext-issued': {
          ok: true,
          status: 200,
          data: mockServiceExtIssuerVc,
        },
        'https://example.com/vp-org': {
          ok: true,
          status: 200,
          data: mockOrgVcWithoutIssuer,
        },
        'https://ecs-trust-registry/service-credential-schema-credential.json': {
          ok: true,
          status: 200,
          data: mockServiceSchemaSelfIssued,
        },
        'https://ecs-trust-registry/service-ext-issuer-credential-schema-credential.json': {
          ok: true,
          status: 200,
          data: mockServiceSchemaExtIssuer,
        },
        'https://ecs-trust-registry/org-credential-schema-credential.json': {
          ok: true,
          status: 200,
          data: mockOrgSchemaWithoutIssuer,
        },
        'https://vpr-hostname/vpr/v1/cs/js/12345673': {
          ok: true,
          status: 200,
          data: mockCredentialSchemaOrg,
        },
        'https://vpr-hostname/vpr/v1/cs/js/12345678': {
          ok: true,
          status: 200,
          data: mockCredentialSchemaSer,
        },
        'https://example.com/trust-registry': { ok: true, status: 200, data: {} },
        'http://testTrust.com/perm/v1/find_with_did?did=did%3Aweb%3Aservice.self-issued.example.com': {
          ok: true,
          status: 200,
          data: mockPermission,
        },
        'http://testTrust.com/cs/v1/get': { ok: true, status: 200, data: mockCredentialSchemaOrg },
      })

      // Execute method under test
      const result = await resolve(didExtIssuer, {
        trustRegistryUrl: 'http://testTrust.com',
        didResolver,
        agentContext,
      })
      expect(resolverInstanceSpy).toHaveBeenCalledWith(didExtIssuer)
      expect(resolverInstanceSpy).toHaveBeenCalledWith(didSelfIssued)
      expect(resolverInstanceSpy).toHaveBeenCalledTimes(2)
      expect(result).toEqual(
        expect.objectContaining({
          verified: true,
          ...mockDidDocumentSelfIssuedExtIssuer,
          service: {
            type: ECS.SERVICE,
            issuer: didSelfIssued,
            credentialSubject: mockServiceExtIssuerVc.verifiableCredential[0].credentialSubject,
          },
          serviceProvider: {
            type: ECS.ORG,
            issuer: didSelfIssued,
            credentialSubject: mockOrgVcWithoutIssuer.verifiableCredential[0].credentialSubject,
          },
        }),
      )
    })
  })
})
