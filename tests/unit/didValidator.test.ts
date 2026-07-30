import { Resolver } from 'did-resolver'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

import {
  CREDENTIAL_FORMAT_LDP_VC,
  ECS,
  IVerreLogger,
  ParticipantRole,
  resolveDID,
  TrustErrorCode,
  TrustResolutionOutcome,
} from '../../src'
import { resolverInstance } from '../../src/libraries'
import { InMemoryCache } from '../../src/utils/helper'
import { identifySchema } from '../../src/utils/validateSchema'
import * as signatureVerifier from '../../src/utils/verifier'
import {
  createRegistriesWithAdapter,
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
  mockW3cJsonSchemaV2,
  setupAgent,
  verifiablePublicRegistries,
  mockParticipant,
} from '../__mocks__'

const mockResolversByDid: Record<string, any> = {
  [didExtIssuer]: { ...mockResolverExtIssuer },
  [didSelfIssued]: { ...mockResolverSelfIssued },
}

describe('DidValidator', () => {
  describe('resolver method in mocked environment', () => {
    beforeEach(async () => {
      // Mock verifySignature function since there is no credential signature
      vi.spyOn(signatureVerifier, 'verifySignature').mockResolvedValue({ result: true })

      // Mock global fetch
      fetchMocker.enable()
    })

    afterEach(() => {
      fetchMocker.reset()
      fetchMocker.disable()
      vi.clearAllMocks()
      resolverInstance.clear()
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
        'https://www.w3.org/ns/credentials/json-schema/v2.json': {
          ok: true,
          status: 200,
          data: mockW3cJsonSchemaV2,
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
        'https://testtrust.com/v4/participant/list?did=did%3Aweb%3Aservice.self-issued.example.com&role=ISSUER&limit=1&schema_id=12345678':
          { ok: true, status: 200, data: mockParticipant },
        'https://testtrust.com/v4/participant/list?did=did%3Aweb%3Aservice.self-issued.example.com&role=ISSUER&limit=1&schema_id=12345671':
          { ok: true, status: 200, data: mockParticipant },
      })

      // Execute method under test
      const result = await resolveDID(didSelfIssued, {
        verifiablePublicRegistries,
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
            validFrom: mockServiceVcSelfIssued.verifiableCredential[0].issuanceDate,
            validUntil: mockServiceVcSelfIssued.verifiableCredential[0].expirationDate,
            raw: mockServiceVcSelfIssued.verifiableCredential[0],
          },
          serviceProvider: {
            schemaType: ECS.ORG,
            id: didSelfIssued,
            issuer: didSelfIssued,
            ...mockOrgVc.verifiableCredential[0].credentialSubject,
            validFrom: mockOrgVc.verifiableCredential[0].issuanceDate,
            validUntil: mockOrgVc.verifiableCredential[0].expirationDate,
            raw: mockOrgVc.verifiableCredential[0],
          },
        }),
      )
    })

    it('should report which credentials failed validation, not just an overall outcome.', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async (did: string) => {
        return mockResolversByDid[did]
      })
      vi.spyOn(signatureVerifier, 'verifySignature').mockResolvedValue({
        result: false,
        error: 'Ed25519 signature verification failed',
        failedCredentials: [
          {
            id: 'https://example.tr/credentials/OrganizationJsonSchemaCredential',
            format: CREDENTIAL_FORMAT_LDP_VC,
            error: 'Ed25519 signature verification failed',
            errorCode: TrustErrorCode.VERIFICATION_FAILED,
          },
        ],
      })
      fetchMocker.setMockResponses({
        'https://example.com/vp-ser-self-issued': { ok: true, status: 200, data: mockServiceVcSelfIssued },
        'https://example.com/vp-org': { ok: true, status: 200, data: mockOrgVc },
      })

      const result = await resolveDID(didSelfIssued, { verifiablePublicRegistries })

      expect(result.verified).toBe(false)
      expect(result.outcome).toBe(TrustResolutionOutcome.INVALID)
      expect(result.metadata?.errorMessage).toBeDefined()

      expect(result.failedCredentials).toHaveLength(2)
      expect(result.failedCredentials?.[0]).toEqual({
        id: 'https://example.tr/credentials/OrganizationJsonSchemaCredential',
        format: CREDENTIAL_FORMAT_LDP_VC,
        error: 'Ed25519 signature verification failed',
        errorCode: TrustErrorCode.VERIFICATION_FAILED,
      })
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
        'https://www.w3.org/ns/credentials/json-schema/v2.json': {
          ok: true,
          status: 200,
          data: mockW3cJsonSchemaV2,
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
        'https://testtrust.com/v4/participant/list?did=did%3Aweb%3Aservice.self-issued.example.com&role=ISSUER&limit=1&schema_id=12345678':
          { ok: true, status: 200, data: mockParticipant },
        'https://testtrust.com/v4/participant/list?did=did%3Aweb%3Aservice.self-issued.example.com&role=ISSUER&limit=1&schema_id=12345673':
          { ok: true, status: 200, data: mockParticipant },
      })

      // Execute method under test
      const result = await resolveDID(didExtIssuer, { verifiablePublicRegistries })
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
            validFrom: mockServiceExtIssuerVc.verifiableCredential[0].issuanceDate,
            validUntil: mockServiceExtIssuerVc.verifiableCredential[0].expirationDate,
            raw: mockServiceExtIssuerVc.verifiableCredential[0],
          },
          serviceProvider: {
            schemaType: ECS.ORG,
            id: didSelfIssued,
            issuer: didSelfIssued,
            ...mockOrgVcWithoutIssuer.verifiableCredential[0].credentialSubject,
            validFrom: mockOrgVcWithoutIssuer.verifiableCredential[0].issuanceDate,
            validUntil: mockOrgVcWithoutIssuer.verifiableCredential[0].expirationDate,
            raw: mockOrgVcWithoutIssuer.verifiableCredential[0],
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
        'https://www.w3.org/ns/credentials/json-schema/v2.json': {
          ok: true,
          status: 200,
          data: mockW3cJsonSchemaV2,
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
        'https://testtrust.com/v4/participant/list?did=did%3Aweb%3Aservice.self-issued.example.com&role=ISSUER&limit=1&schema_id=12345678':
          {
            ok: true,
            status: 200,
            data: mockParticipant,
          },
        'https://testtrust.com/v4/participant/list?did=did%3Aweb%3Aservice.self-issued.example.com&role=ISSUER&limit=1&schema_id=12345673':
          {
            ok: true,
            status: 200,
            data: mockParticipant,
          },
      })

      // Execute method under test
      const result = await resolveDID(didExtIssuer, {
        verifiablePublicRegistries,
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
            validFrom: mockServiceExtIssuerVc.verifiableCredential[0].issuanceDate,
            validUntil: mockServiceExtIssuerVc.verifiableCredential[0].expirationDate,
            raw: mockServiceExtIssuerVc.verifiableCredential[0],
          },
          serviceProvider: {
            schemaType: ECS.ORG,
            id: didSelfIssued,
            issuer: didSelfIssued,
            ...mockOrgVcWithoutIssuer.verifiableCredential[0].credentialSubject,
            validFrom: mockOrgVcWithoutIssuer.verifiableCredential[0].issuanceDate,
            validUntil: mockOrgVcWithoutIssuer.verifiableCredential[0].expirationDate,
            raw: mockOrgVcWithoutIssuer.verifiableCredential[0],
          },
        }),
      )

      // Add digest verification failure scenario
      const verifyDigestSRISpy = vi.spyOn(signatureVerifier, 'verifyDigestSRI')
      await resolveDID(didExtIssuer, {
        verifiablePublicRegistries,
        skipDigestSRICheck: true,
      })
      expect(verifyDigestSRISpy).not.toHaveBeenCalled()
    })
  })

  describe('registry adapter', () => {
    beforeEach(() => {
      vi.spyOn(signatureVerifier, 'verifySignature').mockResolvedValue({ result: true })
      fetchMocker.enable()
    })

    afterEach(() => {
      fetchMocker.reset()
      fetchMocker.disable()
      vi.clearAllMocks()
      resolverInstance.clear()
    })

    const registriesFor = (ecosystemBySchemaId: Record<string, string>) =>
      createRegistriesWithAdapter({
        fetchSchema: async (url: string) => {
          if (url.includes('12345678')) return JSON.stringify(mockCredentialSchemaSer)
          if (url.includes('12345671')) return JSON.stringify(mockCredentialSchemaOrg)
          throw new Error(`Unexpected schema URL in adapter: ${url}`)
        },
        fetchParticipant: async () => ({
          role: ParticipantRole.ISSUER,
          created: '2000-11-18T15:26:01.487Z',
        }),
        fetchSchemaEcosystemDid: async (schemaId: string) => ecosystemBySchemaId[schemaId],
      })

    const allowlistMockResponses = {
      'https://example.com/vp-ser-self-issued': { ok: true, status: 200, data: mockServiceVcSelfIssued },
      'https://example.com/vp-ser-ext-issued': { ok: true, status: 200, data: mockServiceExtIssuerVc },
      'https://example.com/vp-org': { ok: true, status: 200, data: mockOrgVc },
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
        data: mockOrgSchema,
      },
      'https://www.w3.org/ns/credentials/json-schema/v2.json': {
        ok: true,
        status: 200,
        data: mockW3cJsonSchemaV2,
      },
    }

    it('should call adapter methods instead of HTTP for schema and permission', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async (did: string) => {
        return mockResolversByDid[did]
      })

      const mockLogger: IVerreLogger = {
        debug: vi.fn(),
        info: vi.fn(),
        warn: vi.fn(),
        error: vi.fn(),
      }

      const fetchSchemaSpy = vi.fn(async (url: string) => {
        if (url.includes('12345678')) return JSON.stringify(mockCredentialSchemaSer)
        if (url.includes('12345671')) return JSON.stringify(mockCredentialSchemaOrg)
        throw new Error(`Unexpected schema URL in adapter: ${url}`)
      })

      const fetchParticipantSpy = vi.fn(async () => ({
        role: ParticipantRole.ISSUER,
        created: '2000-11-18T15:26:01.487Z',
      }))

      const registriesWithAdapter = createRegistriesWithAdapter({
        fetchSchema: fetchSchemaSpy,
        fetchParticipant: fetchParticipantSpy,
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
        'https://www.w3.org/ns/credentials/json-schema/v2.json': {
          ok: true,
          status: 200,
          data: mockW3cJsonSchemaV2,
        },
      })

      const result = await resolveDID(didSelfIssued, {
        verifiablePublicRegistries: registriesWithAdapter,
        skipDigestSRICheck: true,
        logger: mockLogger,
      })

      expect(result.verified).toBe(true)
      expect(result.outcome).toBe(TrustResolutionOutcome.VERIFIED)

      // Adapter methods were invoked — no HTTP to the indexer
      expect(fetchSchemaSpy).toHaveBeenCalled()
      expect(fetchParticipantSpy).toHaveBeenCalled()

      // Logger confirms the adapter path was taken
      expect(mockLogger.debug).toHaveBeenCalledWith(
        'Using registry adapter for participant check',
        expect.objectContaining({ schemaId: expect.any(String), did: didSelfIssued }),
      )
    })

    it('classifies ECS only for allowlisted ecosystems, including the external issuer path', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async (did: string) => {
        return mockResolversByDid[did]
      })

      fetchMocker.setMockResponses(allowlistMockResponses)

      const trusted = { did: 'did:example:ecosystem', vpr: 'https://vpr-hostname/vpr' }

      const allowed = await resolveDID(didSelfIssued, {
        verifiablePublicRegistries: registriesFor({ '12345678': trusted.did, '12345671': trusted.did }),
        skipDigestSRICheck: true,
        ecsEcosystems: [trusted],
      })
      expect(allowed.verified).toBe(true)
      expect(allowed.service?.schemaType).toBe(ECS.SERVICE)

      const denied = await resolveDID(didSelfIssued, {
        verifiablePublicRegistries: registriesFor({
          '12345678': 'did:example:rogue',
          '12345671': 'did:example:rogue',
        }),
        skipDigestSRICheck: true,
        ecsEcosystems: [trusted],
      })
      expect(denied.verified).toBe(false)

      // the external issuer is resolved through a nested call: the allowlist must reach it too
      const deniedExternal = await resolveDID(didExtIssuer, {
        verifiablePublicRegistries: registriesFor({
          '12345678': trusted.did,
          '12345671': 'did:example:rogue',
        }),
        skipDigestSRICheck: true,
        ecsEcosystems: [trusted],
      })
      expect(deniedExternal.serviceProvider).toBeUndefined()
    })

    it('does not serve a cached resolution to a caller using a different whitelist', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async (did: string) => {
        return mockResolversByDid[did]
      })
      fetchMocker.setMockResponses(allowlistMockResponses)

      const cache = new InMemoryCache()
      const registries = registriesFor({ '12345678': 'did:example:rogue', '12345671': 'did:example:rogue' })

      const open = await resolveDID(didSelfIssued, {
        verifiablePublicRegistries: registries,
        skipDigestSRICheck: true,
        cache,
      })
      expect(open.verified).toBe(true)

      const restricted = await resolveDID(didSelfIssued, {
        verifiablePublicRegistries: registries,
        skipDigestSRICheck: true,
        cache,
        ecsEcosystems: [{ did: 'did:example:ecosystem', vpr: 'https://vpr-hostname/vpr' }],
      })
      expect(restricted.verified).toBe(false)
    })

    it('fails loudly when a whitelist is configured without a registry adapter', async () => {
      await expect(
        identifySchema(mockCredentialSchemaSer, {
          ecsEcosystems: [{ did: 'did:example:ecosystem', vpr: 'https://vpr-hostname/vpr' }],
          schemaId: '12345678',
          vprId: 'https://vpr-hostname/vpr',
        }),
      ).rejects.toThrow('requires a registry adapter')
    })
  })

  describe('resolver method with fully askar initialized agent', () => {
    it('should resolve a did:web using an agent with Askar in-memory wallet', async () => {
      const agent = await setupAgent({ name: 'InMemoryTestAgent' })

      const did = 'did:web:example.com'
      const result = await resolveDID(did, {})

      // Validate result
      expect(result).toHaveProperty('didDocument')
      expect(result.verified).toBe(false)
      expect(result.outcome).toBe(TrustResolutionOutcome.INVALID)

      // Clean up
      await agent.shutdown()
      await agent.modules.askar.deleteStore()
    })
  })
})
