import { Agent, AgentContext } from '@credo-ts/core'
import { Resolver } from 'did-resolver'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

import { ECS, resolveDID, TrustResolutionOutcome, verifyDidAuthorization } from '../../src'
import * as signatureVerifier from '../../src/utils/verifier'
import {
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
  mockResolverSelfIssued,
  mockServiceSchemaExtIssuer,
  mockServiceExtIssuerVc,
  mockServiceSchemaSelfIssued,
  mockServiceVcSelfIssued,
  setupAgent,
  verifiablePublicRegistries,
  mockPermission,
} from '../__mocks__'

const mockResolversByDid: Record<string, any> = {
  [didExtIssuer]: { ...mockResolverExtIssuer },
  [didSelfIssued]: { ...mockResolverSelfIssued },
}

describe('DidValidator', () => {
  let agent: Agent
  let agentContext: AgentContext

  describe('resolver method in mocked environment', () => {
    beforeEach(async () => {
      // Create an agent for Credo-TS using the DID resolver
      agent = await setupAgent({
        name: 'DID Service Test',
      })
      agentContext = agent.dependencyManager.resolve(AgentContext)

      // Mock verifySignature function since there is no credential signature
      vi.spyOn(signatureVerifier, 'verifySignature').mockResolvedValue({ result: true })

      // Mock global fetch
      fetchMocker.enable()
    })

    afterEach(() => {
      fetchMocker.reset()
      fetchMocker.disable()
      vi.clearAllMocks()
    })

    it('should work correctly when the issuer is equal to "did" over testing network.', async () => {
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
        'https://testTrust.com/v1/cs/js/12345671': {
          ok: true,
          status: 200,
          data: mockCredentialSchemaOrg,
        },
        'https://testTrust.com/v1/cs/js/12345678': {
          ok: true,
          status: 200,
          data: mockCredentialSchemaSer,
        },
        'https://example.com/trust-registry': { ok: true, status: 200, data: {} },
        'https://testtrust.com/v1/perm/v1/list?did=did%3Aweb%3Aservice.self-issued.example.com&type=ISSUER&response_max_size=1&schema_id=12345678':
          { ok: true, status: 200, data: mockPermission },
        'https://testtrust.com/v1/perm/v1/list?did=did%3Aweb%3Aservice.self-issued.example.com&type=ISSUER&response_max_size=1&schema_id=12345671':
          { ok: true, status: 200, data: mockPermission },
      })

      // Execute method under test
      const result = await resolveDID(didSelfIssued, {
        verifiablePublicRegistries,
        agentContext,
      })
      expect(resolverInstanceSpy).toHaveBeenCalledWith(didSelfIssued)
      expect(resolverInstanceSpy).toHaveBeenCalledTimes(1)
      expect(result).toEqual(
        expect.objectContaining({
          verified: true,
          outcome: TrustResolutionOutcome.VERIFIED,
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
        'https://testTrust.com/v1/cs/js/12345673': {
          ok: true,
          status: 200,
          data: mockCredentialSchemaOrg,
        },
        'https://testTrust.com/v1/cs/js/12345678': {
          ok: true,
          status: 200,
          data: mockCredentialSchemaSer,
        },
        'https://testtrust.com/v1/perm/v1/list?did=did%3Aweb%3Aservice.self-issued.example.com&type=ISSUER&response_max_size=1&schema_id=12345678':
          { ok: true, status: 200, data: mockPermission },
        'https://testtrust.com/v1/perm/v1/list?did=did%3Aweb%3Aservice.self-issued.example.com&type=ISSUER&response_max_size=1&schema_id=12345673':
          { ok: true, status: 200, data: mockPermission },
      })

      // Execute method under test
      const result = await resolveDID(didExtIssuer, { verifiablePublicRegistries, agentContext })
      expect(resolverInstanceSpy).toHaveBeenCalledWith(didExtIssuer)
      expect(resolverInstanceSpy).toHaveBeenCalledWith(didSelfIssued)
      expect(resolverInstanceSpy).toHaveBeenCalledTimes(2)
      expect(result).toEqual(
        expect.objectContaining({
          verified: true,
          outcome: TrustResolutionOutcome.VERIFIED,
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

    it('should work correctly when the issuer is not "did" with different verifiablePublicRegistries.', async () => {
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
        'https://testTrust.com/v1/cs/js/12345673': {
          ok: true,
          status: 200,
          data: mockCredentialSchemaOrg,
        },
        'https://testTrust.com/v1/cs/js/12345678': {
          ok: true,
          status: 200,
          data: mockCredentialSchemaSer,
        },
        'https://testtrust.com/v1/perm/v1/list?did=did%3Aweb%3Aservice.self-issued.example.com&type=ISSUER&response_max_size=1&schema_id=12345678':
          {
            ok: true,
            status: 200,
            data: mockPermission,
          },
        'https://testtrust.com/v1/perm/v1/list?did=did%3Aweb%3Aservice.self-issued.example.com&type=ISSUER&response_max_size=1&schema_id=12345673':
          {
            ok: true,
            status: 200,
            data: mockPermission,
          },
      })

      // Execute method under test
      const result = await resolveDID(didExtIssuer, {
        verifiablePublicRegistries,
        agentContext,
      })
      expect(resolverInstanceSpy).toHaveBeenCalledWith(didExtIssuer)
      expect(resolverInstanceSpy).toHaveBeenCalledWith(didSelfIssued)
      expect(resolverInstanceSpy).toHaveBeenCalledTimes(2)
      expect(result).toEqual(
        expect.objectContaining({
          verified: true,
          outcome: TrustResolutionOutcome.VERIFIED,
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

    it('should work correctly when ....', async () => {
      // TODO: when integrate verifyDidAuthorization inside resolve, this test should be removed
      // mocked data
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async (did: string) => {
        return mockResolversByDid[did]
      })
      fetchMocker.setMockResponses({
        'https://example.com/vp-org': {
          ok: true,
          status: 200,
          data: mockOrgVc,
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
        'https://vpr-hostname/vpr/perm/v1/list?did=did%3Aweb%3Aservice.self-issued.example.com&type=ISSUER&response_max_size=1&schema_id=12345673':
          {
            ok: true,
            status: 200,
            data: mockPermission,
          },
        'https://vpr-hostname/vpr/perm/v1/list?did=did%3Aweb%3Aservice.self-issued.example.com&type=ISSUER&response_max_size=1&schema_id=12345678':
          {
            ok: true,
            status: 200,
            data: mockPermission,
          },
      })

      // Execute method under test
      const result = await verifyDidAuthorization(didSelfIssued)
      expect(result).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            permissions: expect.arrayContaining([
              expect.objectContaining({
                type: 'ISSUER',
              }),
            ]),
          }),
        ]),
      )
    })
  })

  describe('resolver method with fully askar initialized agent', () => {
    it('should resolve a did:web using an agent with Askar in-memory wallet', async () => {
      const agent = await setupAgent({ name: 'InMemoryTestAgent' })

      const agentContext = agent.dependencyManager.resolve(AgentContext)
      const did = 'did:web:example.com'
      const result = await resolveDID(did, {
        agentContext,
      })

      // Validate result
      expect(result).toHaveProperty('didDocument')
      expect(result.verified).toBe(false)
      expect(result.outcome).toBe(TrustResolutionOutcome.INVALID)

      // Clean up
      await agent.shutdown()
      await agent.wallet.delete()
    })
  })
})
