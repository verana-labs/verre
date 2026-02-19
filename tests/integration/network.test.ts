import {
  Agent,
  AgentContext,
  DidDocument,
  DidResolverService,
  W3cJsonLdVerifiablePresentation,
} from '@credo-ts/core'
import { Resolver } from 'did-resolver'
import { describe, it, beforeAll, afterAll, vi, expect } from 'vitest'

import {
  fetchJson,
  PermissionType,
  resolveCredential,
  resolveDID,
  TrustResolutionOutcome,
  verifyPermissions,
} from '../../src'
import {
  fetchMocker,
  integrationDidDoc,
  jsonSchemaCredentialOrg,
  jsonSchemaCredentialService,
  linkedVpOrg,
  linkedVpService,
  mockPermission,
  setupAgent as setupAndInitializeAgent,
  verifiablePublicRegistries,
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

describe('Integration with Verana Blockchain', () => {
  let agentContext: AgentContext
  beforeAll(async () => {
    // Configure an in-memory wallet for the test agent
    agent = await setupAndInitializeAgent({ name: 'InMemoryTestAgent' })

    // Mock global fetch
    fetchMocker.enable()

    agentContext = agent.dependencyManager.resolve(AgentContext)
  })

  afterAll(async () => {
    await agent?.shutdown()
    await agent?.modules.askar?.deleteStore()
    fetchMocker.reset()
    fetchMocker.disable()
    vi.clearAllMocks()
  })

  it('should perform a full integration self signed by resolving a real DID and validating the schema', async () => {
    // Use this DID to validate real-world service resolution scenarios
    const did =
      'did:webvh:QmUGoLH1vu3APBWo3PXC7pTJ4C1tPqxPxBnZ68s8eKBz1V:dm.gov-id-verifier.demos.dev.2060.io'
    // Setup spy methods
    const resolveSpy = vi.spyOn(Resolver.prototype, 'resolve')

    const result = await resolveDID(did, {
      verifiablePublicRegistries,
      agentContext,
    })

    // Validate result
    expect(resolveSpy).toHaveBeenCalledTimes(2)
    expect(resolveSpy).toHaveBeenCalledWith(did)
    expect(result.verified).toBe(true)
    expect(result.outcome).toBe(TrustResolutionOutcome.VERIFIED)
  }, 50000)

  it('should integrate with Verana testnet and retrieve the nested schema from the blockchain', async () => {
    const did = 'did:web:bcccdd780017.ngrok-free.app'

    // Create a mock object representing a didDocument
    // Mock the Resolver's resolve method to return a predefined DID Document for deterministic testing
    vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async () => {
      return {
        didResolutionMetadata: {},
        didDocumentMetadata: {},
        didDocument: integrationDidDoc,
      }
    })
    // Mock the DidResolverService's resolve method to return a constructed DidDocument instance
    vi.spyOn(DidResolverService.prototype, 'resolve').mockImplementation(async () => {
      return {
        didResolutionMetadata: {},
        didDocumentMetadata: {},
        didDocument: new DidDocument({ ...integrationDidDoc, context: integrationDidDoc['@context'] }),
      }
    })

    // Mock HTTP responses for schema and verifiable presentation endpoints to avoid real network calls
    fetchMocker.setMockResponses({
      'https://bcccdd780017.ngrok-free.app/self-tr/ecs-service-c-vp.json': {
        ok: true,
        status: 200,
        data: linkedVpService,
      },
      'https://bcccdd780017.ngrok-free.app/self-tr/ecs-org-c-vp.json': {
        ok: true,
        status: 200,
        data: linkedVpOrg,
      },
      'https://bcccdd780017.ngrok-free.app/self-tr/schemas-example-service.json': {
        ok: true,
        status: 200,
        data: jsonSchemaCredentialService,
      },
      'https://bcccdd780017.ngrok-free.app/self-tr/schemas-example-org.json': {
        ok: true,
        status: 200,
        data: jsonSchemaCredentialOrg,
      },
      'https://idx.testnet.verana.network/verana/perm/v1/list?did=did%3Aweb%3Abcccdd780017.ngrok-free.app&type=ISSUER&response_max_size=1&schema_id=13':
        {
          ok: true,
          status: 200,
          data: mockPermission,
        },
      'https://idx.testnet.verana.network/verana/perm/v1/list?did=did%3Aweb%3Abcccdd780017.ngrok-free.app&type=ISSUER&response_max_size=1&schema_id=14':
        {
          ok: true,
          status: 200,
          data: mockPermission,
        },
    })

    const result = await resolveDID(did, {
      verifiablePublicRegistries,
      agentContext,
    })

    // Validate result
    expect(result).toHaveProperty('didDocument')
    expect(result).toEqual(
      expect.objectContaining({
        didDocument: integrationDidDoc,
        verified: true,
        outcome: TrustResolutionOutcome.VERIFIED_TEST,
        service: {
          ...linkedVpService?.verifiableCredential?.[0]?.credentialSubject,
          issuer: did,
          schemaType: 'ecs-service',
        },
        serviceProvider: {
          ...linkedVpOrg?.verifiableCredential?.[0]?.credentialSubject,
          issuer: did,
          schemaType: 'ecs-org',
        },
      }),
    )

    // Cached testing
    const cachedResult = await resolveDID(did, {
      verifiablePublicRegistries,
      agentContext,
      cached: true,
    })
    expect(cachedResult.verified).toBe(true)
  }, 10000)

  it('should resolve and validate a real self-signed credential end-to-end', async () => {
    const presentation = await fetchJson<W3cJsonLdVerifiablePresentation>(
      'https://dm.chatbot.demos.dev.2060.io/vt/ecs-service-c-vp.json',
    )

    // TODO: Remove once self-permissions are implemented in vs-agent
    fetchMocker.setMockResponses({
      'https://dm.chatbot.demos.dev.2060.io/vt/perm/v1/list?did=did%3Aweb%3Adm.chatbot.demos.dev.2060.io&type=ISSUER&response_max_size=1&schema_id=ecs-service':
        {
          ok: true,
          status: 200,
          data: mockPermission,
        },
    })
    const cred = Array.isArray(presentation.verifiableCredential)
      ? presentation.verifiableCredential[0]
      : presentation.verifiableCredential

    const result = await resolveCredential(cred, {
      verifiablePublicRegistries,
      agentContext,
    })

    // Validate result
    expect(result.verified).toBe(true)
    expect(result.outcome).toBe(TrustResolutionOutcome.NOT_TRUSTED)
  }, 10000)

  it('should return verified: true when permission checks succeed', async () => {
    const result = await verifyPermissions({
      did: 'did:webvh:QmS8DRrqwZuTNLk5ZinD91F2o3xn7XwCVCS5CHGfJHyfhb:dm.gov-id-tr.demos.dev.2060.io',
      jsonSchemaCredentialId: 'https://dm.gov-id-tr.demos.dev.2060.io/vt/schemas-gov-id-jsc.json',
      issuanceDate: '2025-11-22T00:22:56.885Z',
      verifiablePublicRegistries,
      permissionType: PermissionType.ISSUER,
    })
    expect(result.verified).toBe(true)
  })
})
