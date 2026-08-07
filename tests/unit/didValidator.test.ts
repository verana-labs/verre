import { Resolver } from 'did-resolver'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

import {
  CREDENTIAL_FORMAT_LDP_VC,
  ECS,
  IVerreLogger,
  ParticipantRole,
  ParticipantState,
  resolveDID,
  TrustErrorCode,
  TrustResolutionOutcome,
} from '../../src'
import { resolverInstance } from '../../src/libraries'
import { computeCredentialDigestJCS } from '../../src/utils/credentialDigest'
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

// [IDX-VT-EVAL-1] resolution now demands a ledger-anchored digest. Anchoring at the same instant the
// participant fixtures already encode keeps every participant/list URL below unchanged.
const ANCHORED_AT = '2024-02-08T18:38:46+01:00'
// deliberately different from any credential's issuanceDate, so a test can prove the ledger
// instant is what reaches the participant lookup
const LEDGER_ANCHORED_AT = '2023-05-05T00:00:00.000Z'
const IDX = 'https://idx.testnet.verana.network'

const anchorMocks = (...vcs: unknown[]) => {
  const mocks: Record<string, { ok: boolean; status: number; data: unknown }> = {}
  for (const id of [12345678, 12345671, 12345673]) {
    mocks[`${IDX}/v4/credential-schema/get/${id}`] = {
      ok: true,
      status: 200,
      data: { schema: { id, ecosystem_id: 1, digest_algorithm: 'sha384', json_schema: '' } },
    }
  }
  for (const vc of vcs) {
    const digest = computeCredentialDigestJCS(vc as never, 'sha384')
    mocks[`${IDX}/v4/di/get/${encodeURIComponent(digest)}`] = {
      ok: true,
      status: 200,
      data: { digest: { digest, created: ANCHORED_AT } },
    }
  }
  return mocks
}

const ALL_ANCHOR_MOCKS = anchorMocks(
  mockServiceVcSelfIssued.verifiableCredential[0],
  mockOrgVc.verifiableCredential[0],
  mockServiceExtIssuerVc.verifiableCredential[0],
)

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
        ...ALL_ANCHOR_MOCKS,
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
        'https://idx.testnet.verana.network/v4/credential-schema/js/12345671': {
          ok: true,
          status: 200,
          data: mockCredentialSchemaOrg,
        },
        'https://idx.testnet.verana.network/v4/credential-schema/js/12345678': {
          ok: true,
          status: 200,
          data: mockCredentialSchemaSer,
        },
        'https://example.com/trust-registry': { ok: true, status: 200, data: {} },
        'https://idx.testnet.verana.network/v4/participant/list?did=did%3Aweb%3Aservice.self-issued.example.com&role=ISSUER&schema_id=12345678&when=2024-02-08T18%3A38%3A46%2B01%3A00':
          { ok: true, status: 200, data: mockParticipant },
        'https://idx.testnet.verana.network/v4/participant/list?did=did%3Aweb%3Aservice.self-issued.example.com&role=ISSUER&schema_id=12345671&when=2024-02-08T18%3A38%3A46%2B01%3A00':
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
          service: expect.objectContaining({
            ecs: ECS.SERVICE,
            id: mockServiceVcSelfIssued.verifiableCredential[0].id,
            issuer: didSelfIssued,
            subject: expect.objectContaining(
              mockServiceVcSelfIssued.verifiableCredential[0].credentialSubject,
            ),
            validFrom: mockServiceVcSelfIssued.verifiableCredential[0].issuanceDate,
            validUntil: mockServiceVcSelfIssued.verifiableCredential[0].expirationDate,
            raw: mockServiceVcSelfIssued.verifiableCredential[0],
          }),
          serviceProvider: expect.objectContaining({
            ecs: ECS.ORG,
            id: mockOrgVc.verifiableCredential[0].id,
            issuer: didSelfIssued,
            subject: expect.objectContaining(mockOrgVc.verifiableCredential[0].credentialSubject),
            validFrom: mockOrgVc.verifiableCredential[0].issuanceDate,
            validUntil: mockOrgVc.verifiableCredential[0].expirationDate,
            raw: mockOrgVc.verifiableCredential[0],
          }),
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
        ...ALL_ANCHOR_MOCKS,
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
        ...ALL_ANCHOR_MOCKS,
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
        'https://idx.testnet.verana.network/v4/credential-schema/js/12345673': {
          ok: true,
          status: 200,
          data: mockCredentialSchemaOrg,
        },
        'https://idx.testnet.verana.network/v4/credential-schema/js/12345678': {
          ok: true,
          status: 200,
          data: mockCredentialSchemaSer,
        },
        'https://idx.testnet.verana.network/v4/participant/list?did=did%3Aweb%3Aservice.self-issued.example.com&role=ISSUER&schema_id=12345678&when=2024-02-08T18%3A38%3A46%2B01%3A00':
          { ok: true, status: 200, data: mockParticipant },
        'https://idx.testnet.verana.network/v4/participant/list?did=did%3Aweb%3Aservice.self-issued.example.com&role=ISSUER&schema_id=12345673&when=2024-02-08T18%3A38%3A46%2B01%3A00':
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
          service: expect.objectContaining({
            ecs: ECS.SERVICE,
            id: mockServiceExtIssuerVc.verifiableCredential[0].id,
            issuer: didSelfIssued,
            subject: expect.objectContaining(
              mockServiceExtIssuerVc.verifiableCredential[0].credentialSubject,
            ),
            validFrom: mockServiceExtIssuerVc.verifiableCredential[0].issuanceDate,
            validUntil: mockServiceExtIssuerVc.verifiableCredential[0].expirationDate,
            raw: mockServiceExtIssuerVc.verifiableCredential[0],
          }),
          serviceProvider: expect.objectContaining({
            ecs: ECS.ORG,
            id: mockOrgVcWithoutIssuer.verifiableCredential[0].id,
            issuer: didSelfIssued,
            subject: expect.objectContaining(
              mockOrgVcWithoutIssuer.verifiableCredential[0].credentialSubject,
            ),
            validFrom: mockOrgVcWithoutIssuer.verifiableCredential[0].issuanceDate,
            validUntil: mockOrgVcWithoutIssuer.verifiableCredential[0].expirationDate,
            raw: mockOrgVcWithoutIssuer.verifiableCredential[0],
          }),
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
        ...ALL_ANCHOR_MOCKS,
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
        'https://idx.testnet.verana.network/v4/credential-schema/js/12345673': {
          ok: true,
          status: 200,
          data: mockCredentialSchemaOrg,
        },
        'https://idx.testnet.verana.network/v4/credential-schema/js/12345678': {
          ok: true,
          status: 200,
          data: mockCredentialSchemaSer,
        },
        'https://idx.testnet.verana.network/v4/participant/list?did=did%3Aweb%3Aservice.self-issued.example.com&role=ISSUER&schema_id=12345678&when=2024-02-08T18%3A38%3A46%2B01%3A00':
          {
            ok: true,
            status: 200,
            data: mockParticipant,
          },
        'https://idx.testnet.verana.network/v4/participant/list?did=did%3Aweb%3Aservice.self-issued.example.com&role=ISSUER&schema_id=12345673&when=2024-02-08T18%3A38%3A46%2B01%3A00':
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
          service: expect.objectContaining({
            ecs: ECS.SERVICE,
            id: mockServiceExtIssuerVc.verifiableCredential[0].id,
            issuer: didSelfIssued,
            subject: expect.objectContaining(
              mockServiceExtIssuerVc.verifiableCredential[0].credentialSubject,
            ),
            validFrom: mockServiceExtIssuerVc.verifiableCredential[0].issuanceDate,
            validUntil: mockServiceExtIssuerVc.verifiableCredential[0].expirationDate,
            raw: mockServiceExtIssuerVc.verifiableCredential[0],
          }),
          serviceProvider: expect.objectContaining({
            ecs: ECS.ORG,
            id: mockOrgVcWithoutIssuer.verifiableCredential[0].id,
            issuer: didSelfIssued,
            subject: expect.objectContaining(
              mockOrgVcWithoutIssuer.verifiableCredential[0].credentialSubject,
            ),
            validFrom: mockOrgVcWithoutIssuer.verifiableCredential[0].issuanceDate,
            validUntil: mockOrgVcWithoutIssuer.verifiableCredential[0].expirationDate,
            raw: mockOrgVcWithoutIssuer.verifiableCredential[0],
          }),
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
        listParticipants: async () => [
          {
            id: 1,
            role: ParticipantRole.ISSUER,
            created: '2000-11-18T15:26:01.487Z',
            participant_state: ParticipantState.ACTIVE,
          },
        ],
        fetchDigest: async () => ({ created: ANCHORED_AT }),
        fetchCredentialSchema: async (schemaId: number) => ({
          id: Number(schemaId),
          ecosystemId: 1,
          ecosystemDid: ecosystemBySchemaId[schemaId],
          digestAlgorithm: 'sha384',
          jsonSchema: '',
        }),
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

      const fetchParticipantSpy = vi.fn(async () => [
        {
          id: 1,
          role: ParticipantRole.ISSUER,
          created: '2000-11-18T15:26:01.487Z',
          participant_state: ParticipantState.ACTIVE,
        },
      ])

      const registriesWithAdapter = createRegistriesWithAdapter({
        fetchSchema: fetchSchemaSpy,
        listParticipants: fetchParticipantSpy,
        fetchDigest: async () => ({ created: LEDGER_ANCHORED_AT }),
        fetchCredentialSchema: async () => ({
          id: 1,
          ecosystemId: 1,
          ecosystemDid: 'did:example:ecosystem',
          digestAlgorithm: 'sha384',
          jsonSchema: '',
        }),
      })

      fetchMocker.setMockResponses({
        ...ALL_ANCHOR_MOCKS,
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
      expect(fetchParticipantSpy).toHaveBeenCalledWith(
        expect.anything(),
        didSelfIssued,
        ParticipantRole.ISSUER,
        LEDGER_ANCHORED_AT,
      )

      // Logger confirms the adapter path was taken
      expect(mockLogger.debug).toHaveBeenCalledWith(
        'Using registry adapter for participant check',
        expect.objectContaining({ schemaId: expect.any(Number), did: didSelfIssued }),
      )
    })

    it('classifies ECS only for allowlisted ecosystems, including the external issuer path', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async (did: string) => {
        return mockResolversByDid[did]
      })

      fetchMocker.setMockResponses({ ...allowlistMockResponses, ...ALL_ANCHOR_MOCKS })

      const trusted = { did: 'did:example:ecosystem', vpr: 'vpr:verana:vna-testnet-1' }

      const allowed = await resolveDID(didSelfIssued, {
        verifiablePublicRegistries: registriesFor({ '12345678': trusted.did, '12345671': trusted.did }),
        skipDigestSRICheck: true,
        ecsEcosystems: [trusted],
      })
      expect(allowed.verified).toBe(true)
      expect(allowed.service?.ecs).toBe(ECS.SERVICE)

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

    it('rejects a credential issued after the participant window ends', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async (did: string) => {
        return mockResolversByDid[did]
      })
      fetchMocker.setMockResponses({ ...allowlistMockResponses, ...ALL_ANCHOR_MOCKS })
      vi.setSystemTime(new Date('2020-01-01T00:00:00Z'))

      const registries = createRegistriesWithAdapter({
        fetchSchema: async (url: string) => {
          if (url.includes('12345678')) return JSON.stringify(mockCredentialSchemaSer)
          if (url.includes('12345671')) return JSON.stringify(mockCredentialSchemaOrg)
          throw new Error(`Unexpected schema URL in adapter: ${url}`)
        },
        listParticipants: async () => [
          {
            id: 1,
            role: ParticipantRole.ISSUER,
            created: '2000-11-18T15:26:01.487Z',
            participant_state: ParticipantState.ACTIVE,
          },
        ],
        fetchDigest: async () => ({ created: ANCHORED_AT }),
        fetchCredentialSchema: async () => ({
          id: 1,
          ecosystemId: 1,
          ecosystemDid: 'did:example:ecosystem',
          digestAlgorithm: 'sha384',
          jsonSchema: '',
        }),
      })

      const result = await resolveDID(didSelfIssued, {
        verifiablePublicRegistries: registries,
        skipDigestSRICheck: true,
      })
      vi.useRealTimers()
      expect(result.verified).toBe(false)
    })

    it('fails a credential whose digest was never anchored on the ledger', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async (did: string) => {
        return mockResolversByDid[did]
      })
      fetchMocker.setMockResponses({ ...allowlistMockResponses, ...ALL_ANCHOR_MOCKS })

      const registries = createRegistriesWithAdapter({
        fetchSchema: async (url: string) => {
          if (url.includes('12345678')) return JSON.stringify(mockCredentialSchemaSer)
          if (url.includes('12345671')) return JSON.stringify(mockCredentialSchemaOrg)
          throw new Error(`Unexpected schema URL in adapter: ${url}`)
        },
        listParticipants: async () => [
          {
            id: 1,
            role: ParticipantRole.ISSUER,
            created: '2000-11-18T15:26:01.487Z',
            participant_state: ParticipantState.ACTIVE,
          },
        ],
        fetchDigest: async () => undefined,
        fetchCredentialSchema: async () => ({
          id: 1,
          ecosystemId: 1,
          ecosystemDid: 'did:example:ecosystem',
          digestAlgorithm: 'sha384',
          jsonSchema: '',
        }),
      })

      const result = await resolveDID(didSelfIssued, {
        verifiablePublicRegistries: registries,
        skipDigestSRICheck: true,
      })

      expect(result.verified).toBe(false)
      expect(result.metadata?.errorMessage).toContain('no provable issuance time')
    })

    it('surfaces the VPR evidence on each resolved credential (Scope B)', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async (did: string) => {
        return mockResolversByDid[did]
      })
      fetchMocker.setMockResponses({ ...allowlistMockResponses, ...ALL_ANCHOR_MOCKS })

      const result = await resolveDID(didSelfIssued, {
        verifiablePublicRegistries: registriesFor({
          '12345678': 'did:example:ecosystem',
          '12345671': 'did:example:ecosystem',
        }),
        skipDigestSRICheck: true,
      })

      expect(result.verified).toBe(true)
      // the service self-issued this credential
      expect(result.anchorPattern).toBe('self')

      const service = result.service!
      // id is the VC id, no longer shadowed by the subject DID
      expect(service.id).toBe(mockServiceVcSelfIssued.verifiableCredential[0].id)
      expect(service.subject.id).toBe(mockServiceVcSelfIssued.verifiableCredential[0].credentialSubject.id)
      expect(service.id).not.toBe(service.subject.id)
      // EVAL-1 evidence gathered on the way
      expect(service.digestJCS).toEqual(expect.any(String))
      expect(service.issuedAtTime).toBe(ANCHORED_AT)
      expect(service.credentialSchemaId).toEqual(expect.any(Number))
      expect(service.ecosystemId).toBe(1)
      expect(service.issuerParticipant).toEqual(
        expect.objectContaining({ id: 1, role: ParticipantRole.ISSUER }),
      )
      expect(Array.isArray(service.subjectParticipants)).toBe(true)

      // the linked VPs are surfaced so consumers do not re-fetch them
      expect(result.presentations?.length).toBeGreaterThan(0)
      expect(result.presentations?.[0]).toEqual(
        expect.objectContaining({
          serviceId: expect.any(String),
          endpoint: expect.any(String),
          credentials: expect.arrayContaining([service]),
        }),
      )
    })

    it('takes expiresAtTime from the HOLDER entries anchoring the credential', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async (did: string) => {
        return mockResolversByDid[did]
      })
      fetchMocker.setMockResponses({ ...allowlistMockResponses, ...ALL_ANCHOR_MOCKS })

      const HOLDER_EFFECTIVE_UNTIL = '2025-01-01T00:00:00.000Z'
      const registries = createRegistriesWithAdapter({
        fetchSchema: async (url: string) => {
          if (url.includes('12345678')) return JSON.stringify(mockCredentialSchemaSer)
          if (url.includes('12345671')) return JSON.stringify(mockCredentialSchemaOrg)
          throw new Error(`Unexpected schema URL in adapter: ${url}`)
        },
        listParticipants: async (_schemaId: number, _did: string, role: ParticipantRole) =>
          role === ParticipantRole.HOLDER
            ? [
                {
                  id: 2,
                  role: ParticipantRole.HOLDER,
                  created: '2000-11-18T15:26:01.487Z',
                  effective_until: HOLDER_EFFECTIVE_UNTIL,
                  participant_state: ParticipantState.ACTIVE,
                },
              ]
            : [
                {
                  id: 1,
                  role: ParticipantRole.ISSUER,
                  created: '2000-11-18T15:26:01.487Z',
                  effective_until: '2099-01-01T00:00:00.000Z',
                  participant_state: ParticipantState.ACTIVE,
                },
              ],
        fetchDigest: async () => ({ created: ANCHORED_AT }),
        fetchCredentialSchema: async () => ({
          id: 1,
          ecosystemId: 1,
          ecosystemDid: 'did:example:ecosystem',
          digestAlgorithm: 'sha384',
          jsonSchema: '',
        }),
      })

      const result = await resolveDID(didSelfIssued, {
        verifiablePublicRegistries: registries,
        skipDigestSRICheck: true,
      })

      expect(result.expiresAtTime).toBe(HOLDER_EFFECTIVE_UNTIL)
    })

    it('does not serve a cached resolution to a caller using a different allowlist', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async (did: string) => {
        return mockResolversByDid[did]
      })
      fetchMocker.setMockResponses({ ...allowlistMockResponses, ...ALL_ANCHOR_MOCKS })

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
        ecsEcosystems: [{ did: 'did:example:ecosystem', vpr: 'vpr:verana:vna-testnet-1' }],
      })
      expect(restricted.verified).toBe(false)
    })

    it.each([
      ParticipantState.SLASHED,
      ParticipantState.REVOKED,
      ParticipantState.REPAID,
      ParticipantState.FUTURE,
      ParticipantState.INACTIVE,
      undefined,
    ])('rejects a participant reported as %s', async state => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async (did: string) => {
        return mockResolversByDid[did]
      })
      fetchMocker.setMockResponses({ ...allowlistMockResponses, ...ALL_ANCHOR_MOCKS })

      const registries = createRegistriesWithAdapter({
        fetchSchema: async (url: string) => {
          if (url.includes('12345678')) return JSON.stringify(mockCredentialSchemaSer)
          if (url.includes('12345671')) return JSON.stringify(mockCredentialSchemaOrg)
          throw new Error(`Unexpected schema URL in adapter: ${url}`)
        },
        listParticipants: async () => [
          {
            id: 1,
            role: ParticipantRole.ISSUER,
            created: '2000-11-18T15:26:01.487Z',
            participant_state: state,
          },
        ],
        fetchDigest: async () => ({ created: ANCHORED_AT }),
        fetchCredentialSchema: async () => ({
          id: 1,
          ecosystemId: 1,
          ecosystemDid: 'did:example:ecosystem',
          digestAlgorithm: 'sha384',
          jsonSchema: '',
        }),
      })

      const result = await resolveDID(didSelfIssued, {
        verifiablePublicRegistries: registries,
        skipDigestSRICheck: true,
      })
      expect(result.verified).toBe(false)
    })

    it('fails loudly when an allowlist is configured without a registry adapter', async () => {
      await expect(
        identifySchema(mockCredentialSchemaSer, {
          ecsEcosystems: [{ did: 'did:example:ecosystem', vpr: 'vpr:verana:vna-testnet-1' }],
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
