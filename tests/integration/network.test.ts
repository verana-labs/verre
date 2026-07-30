import { Agent, DidDocument, DidResolverService, W3cJsonLdVerifiablePresentation } from '@credo-ts/core'
import { Resolver } from 'did-resolver'
import { describe, it, beforeAll, afterAll, vi, expect } from 'vitest'

import {
  CREDENTIAL_FORMAT_LDP_VC,
  fetchJson,
  InMemoryCache,
  ParticipantRole,
  resolveCredential,
  resolveDID,
  TrustErrorCode,
  TrustResolutionOutcome,
  verifyParticipant,
} from '../../src'
import {
  fetchMocker,
  getCredoTsDidResolver,
  integrationDidDoc,
  integrationMockResponses,
  linkedVpOrg,
  linkedVpServiceWithInvalidJws,
  mockParticipant,
  setupAgent as setupAndInitializeAgent,
  verifiablePublicRegistries,
  buildV4Fixtures,
  v4TestDocumentLoader,
} from '../__mocks__'

/**
 * Integration Test Documentation
 *
 * This test suite validates the integration of the Verana Blockchain DID resolver and schema retrieval mechanisms.
 *
 * Mocking Strategy:
 * -----------------
 * 1. DID Resolution:
 *    - The DID resolution process is mocked using spies on both the `Resolver` and `DidResolverService` classes.
 *    - This is done to avoid making real network calls to external DID endpoints, ensuring tests are deterministic and fast.
 *    - For the self-signed DID test, the real resolver is used to verify the integration with a real DID.
 *    - For the Verana testnet integration, the resolver is mocked to return a predefined DID Document (`integrationDidDoc`).
 *
 * 2. Fetch Requests:
 *    - The `fetchMocker` utility is used to intercept and mock HTTP requests for schema and verifiable presentation documents.
 *    - This prevents actual HTTP requests to the testnet endpoints and allows us to control the returned data.
 *    - The mock responses correspond to the expected structure of service and organization schemas, as well as linked verifiable presentations.
 */

// --- Globals for test lifecycle ---
let agent: Agent
let didResolver: Resolver

describe('Integration with Verana Blockchain', () => {
  beforeAll(async () => {
    // Configure an in-memory wallet for the test agent
    agent = await setupAndInitializeAgent({ name: 'InMemoryTestAgent', documentLoader: v4TestDocumentLoader })
    didResolver = getCredoTsDidResolver(agent.context)

    // Mock global fetch
    fetchMocker.enable()
  })

  afterAll(async () => {
    await agent?.shutdown()
    await agent?.modules.askar?.deleteStore()
    fetchMocker.reset()
    fetchMocker.disable()
    vi.clearAllMocks()
  })

  // re-enable when a v4-content deployment exists; the pinned DID publishes v3 ECS content
  it.skip('should perform a full integration self signed by resolving a real DID and validating the schema', async () => {
    // Use this DID to validate real-world service resolution scenarios
    const did =
      'did:webvh:QmQfm1rpBg7QquBnwEn8TQCut7VAY4r7y2ujjst4ZTg4o5:dm.gov-id-verifier.demos.dev.2060.io'
    // Setup spy methods
    const resolveSpy = vi.spyOn(Resolver.prototype, 'resolve')

    const result = await resolveDID(did, {
      verifiablePublicRegistries,
    })

    expect(resolveSpy).toHaveBeenCalledTimes(3)
    expect(resolveSpy).toHaveBeenCalledWith(did)
    expect(result.verified).toBe(true)
    expect(result.outcome).toBe(TrustResolutionOutcome.VERIFIED)
  }, 50000)

  it('should integrate with Verana testnet and retrieve the nested schema from the blockchain', async () => {
    const fixtures = await buildV4Fixtures(agent)
    const did = fixtures.did

    vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async () => {
      return {
        didResolutionMetadata: {},
        didDocumentMetadata: {},
        didDocument: fixtures.didDocument,
      }
    })
    vi.spyOn(DidResolverService.prototype, 'resolve').mockImplementation(async () => {
      return {
        didResolutionMetadata: {},
        didDocumentMetadata: {},
        didDocument: fixtures.credoDidDocument,
      }
    })

    fetchMocker.setMockResponses(fixtures.mockResponses)
    const cache = new InMemoryCache()
    const result = await resolveDID(did, {
      verifiablePublicRegistries,
      didResolver,
      cache,
    })

    expect(result).toHaveProperty('didDocument')
    expect(result).toEqual(
      expect.objectContaining({
        didDocument: fixtures.didDocument,
        verified: true,
        outcome: TrustResolutionOutcome.VERIFIED_TEST,
        service: expect.objectContaining({
          schemaType: 'ecs-service',
          name: 'V4 Demo Service',
          logoUri: 'https://v4-agent.example/logo.png',
          issuer: did,
        }),
        serviceProvider: expect.objectContaining({
          schemaType: 'ecs-org',
          name: 'V4 Demo Org',
          registryId: 'REG-1',
          issuer: did,
        }),
      }),
    )

    // Second call should be served entirely from cache: no new fetch calls
    const fetchCountBefore = (global.fetch as any).mock.calls.length
    const cachedResult = await resolveDID(did, {
      verifiablePublicRegistries,
      cache,
    })
    expect(cachedResult.verified).toBe(true)
    expect((global.fetch as any).mock.calls.length).toBe(fetchCountBefore)
  }, 20000)

  it('resolves v3 fixture content as invalid', async () => {
    const did = 'did:web:bcccdd780017.ngrok-free.app'

    vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async () => {
      return {
        didResolutionMetadata: {},
        didDocumentMetadata: {},
        didDocument: integrationDidDoc,
      }
    })
    vi.spyOn(DidResolverService.prototype, 'resolve').mockImplementation(async () => {
      return {
        didResolutionMetadata: {},
        didDocumentMetadata: {},
        didDocument: new DidDocument({ ...integrationDidDoc, context: integrationDidDoc['@context'] }),
      }
    })

    fetchMocker.setMockResponses(integrationMockResponses)
    const result = await resolveDID(did, {
      verifiablePublicRegistries,
      didResolver,
    })

    expect(result.verified).toBe(false)
    expect(result.outcome).toBe(TrustResolutionOutcome.INVALID)
  }, 10000)

  it('should fail integration when a verifiable credential validation fails', async () => {
    const did = 'did:web:bcccdd780017.ngrok-free.app'

    vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async () => {
      return {
        didResolutionMetadata: {},
        didDocumentMetadata: {},
        didDocument: integrationDidDoc,
      }
    })

    vi.spyOn(DidResolverService.prototype, 'resolve').mockImplementation(async () => {
      return {
        didResolutionMetadata: {},
        didDocumentMetadata: {},
        didDocument: new DidDocument({ ...integrationDidDoc, context: integrationDidDoc['@context'] }),
      }
    })

    fetchMocker.setMockResponses({
      'https://bcccdd780017.ngrok-free.app/self-tr/ecs-service-c-vp.json': {
        ok: true,
        status: 200,
        data: linkedVpServiceWithInvalidJws,
      },
      'https://bcccdd780017.ngrok-free.app/self-tr/ecs-org-c-vp.json': {
        ok: true,
        status: 200,
        data: linkedVpOrg,
      },
    })

    const result = await resolveDID(did, {
      verifiablePublicRegistries,
      didResolver,
    })

    expect(result.verified).toBe(false)
    expect(result.outcome).toBe(TrustResolutionOutcome.INVALID)
    expect(result.metadata).toMatchObject({
      errorCode: TrustErrorCode.INVALID,
    })

    expect(result.failedCredentials).toHaveLength(2)
    expect(result.failedCredentials).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          format: CREDENTIAL_FORMAT_LDP_VC,
          error: 'Invalid or missing JWS detached signature',
          errorCode: TrustErrorCode.VERIFICATION_FAILED,
        }),
      ]),
    )
  })

  // re-enable when the deployment exposes the v4 participant endpoints; testnet still serves /perm/v1/list
  it.skip('should resolve and validate a real self-signed credential end-to-end', async () => {
    const presentation = await fetchJson<W3cJsonLdVerifiablePresentation>(
      'https://dm.chatbot.demos.dev.2060.io/vt/ecs-service-c-vp.json',
    )

    // TODO: Remove once self-permissions are implemented in vs-agent
    fetchMocker.setMockResponses({
      'https://dm.chatbot.demos.dev.2060.io/v4/participant/list?did=did%3Aweb%3Adm.chatbot.demos.dev.2060.io&role=ISSUER&limit=1&schema_id=ecs-service':
        {
          ok: true,
          status: 200,
          data: mockParticipant,
        },
    })
    const cred = Array.isArray(presentation.verifiableCredential)
      ? presentation.verifiableCredential[0]
      : presentation.verifiableCredential

    const result = await resolveCredential(cred, {
      verifiablePublicRegistries,
    })

    // Validate result
    expect(result.verified).toBe(true)
    expect(result.outcome).toBe(TrustResolutionOutcome.NOT_TRUSTED)
  }, 10000)

  // re-enable when the deployment exposes the v4 participant endpoints; testnet still serves /perm/v1/list
  it.skip('should return verified: true when permission checks succeed', async () => {
    const result = await verifyParticipant({
      did: 'did:webvh:QmS8DRrqwZuTNLk5ZinD91F2o3xn7XwCVCS5CHGfJHyfhb:dm.gov-id-tr.demos.dev.2060.io',
      jsonSchemaCredentialId: 'https://dm.gov-id-tr.demos.dev.2060.io/vt/schemas-gov-id-jsc.json',
      issuanceDate: '2026-02-20T16:57.885Z',
      verifiablePublicRegistries,
      role: ParticipantRole.ISSUER,
    })
    expect(result.verified).toBe(true)
  })
})
