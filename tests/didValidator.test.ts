import { AskarModule } from '@credo-ts/askar'
import { Agent, AgentContext, DidResolverService, InitConfig } from '@credo-ts/core'
import { agentDependencies } from '@credo-ts/node'
import { ariesAskar } from '@hyperledger/aries-askar-nodejs'
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
  getAskarStoreConfig,
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

  describe('resolver method in mocked environment', () => {
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
            schemaType: ECS.SERVICE,
            id: didSelfIssued,
            issuer: didSelfIssued,
            ...mockServiceVcSelfIssued.verifiableCredential[0].credentialSubject,
          },
          serviceProvider: {
            schemaType: ECS.ORG,
            id: didSelfIssued,
            issuer: didSelfIssued,
            ...mockOrgVc.verifiableCredential[0].credentialSubject,
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
            schemaType: ECS.SERVICE,
            id: didSelfIssued,
            issuer: didSelfIssued,
            ...mockServiceExtIssuerVc.verifiableCredential[0].credentialSubject,
          },
          serviceProvider: {
            schemaType: ECS.ORG,
            id: didSelfIssued,
            issuer: didSelfIssued,
            ...mockOrgVcWithoutIssuer.verifiableCredential[0].credentialSubject,
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
            schemaType: ECS.SERVICE,
            id: didSelfIssued,
            issuer: didSelfIssued,
            ...mockServiceExtIssuerVc.verifiableCredential[0].credentialSubject,
          },
          serviceProvider: {
            schemaType: ECS.ORG,
            id: didSelfIssued,
            issuer: didSelfIssued,
            ...mockOrgVcWithoutIssuer.verifiableCredential[0].credentialSubject,
          },
        }),
      )
    })
  })
  describe('resolver method with fully askar initialized agent', () => {
    it('should resolve a did:web using an agent with Askar in-memory wallet', async () => {
      const walletConfig = getAskarStoreConfig('InMemoryTestAgent', { inMemory: true })
      const config: InitConfig = {
        label: 'InMemoryTestAgent',
        walletConfig,
      }

      const agent = new Agent({
        config,
        dependencies: agentDependencies,
        modules: {
          askar: new AskarModule({ ariesAskar }),
        },
      })
      await agent.initialize()

      const agentContext = agent.dependencyManager.resolve(AgentContext)
      const didResolverService = agent.dependencyManager.resolve(DidResolverService)

      const didResolver = new Resolver({
        web: async did => didResolverService.resolve(agentContext, did),
      })

      const did = 'did:web:example.com'
      const result = await resolve(did, {
        didResolver,
        agentContext,
      })

      // Validate result
      expect(result).toHaveProperty('didDocument')
      expect(result.verified).toBe(false)

      // Clean up
      await agent.shutdown()
      await agent.wallet.delete()
    })
  })
})
