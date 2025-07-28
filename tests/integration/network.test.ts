import { AskarModule } from '@credo-ts/askar'
import { Agent, AgentContext, DidDocument, DidResolverService, InitConfig } from '@credo-ts/core'
import { agentDependencies } from '@credo-ts/node'
import { ariesAskar } from '@hyperledger/aries-askar-nodejs'
import { Resolver } from 'did-resolver'
import { describe, it, beforeAll, afterAll, vi, expect } from 'vitest'

import { resolve } from '../../src/resolver'
import {
  fetchMocker,
  getAskarStoreConfig,
  integrationDidDoc,
  jsonSchemaCredentialOrg,
  jsonSchemaCredentialService,
  linkedVpOrg,
  linkedVpService,
  mockDidDocumentChatbot,
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
    const walletConfig = getAskarStoreConfig('InMemoryTestAgent', { inMemory: true })

    const config: InitConfig = {
      label: 'InMemoryTestAgent',
      walletConfig,
    }

    agent = new Agent({
      config,
      dependencies: agentDependencies,
      modules: {
        askar: new AskarModule({ ariesAskar }),
      },
    })

    await agent.initialize()

    // Mock global fetch
    fetchMocker.enable()

    agentContext = agent.dependencyManager.resolve(AgentContext)
  })

  afterAll(async () => {
    await agent?.shutdown()
    await agent?.wallet?.delete()
    fetchMocker.reset()
    fetchMocker.disable()
    vi.clearAllMocks()
  })

  it('should perform a full integration self signed by resolving a real DID and validating the schema', async () => {
    const did = 'did:web:dm.chatbot.demos.dev.2060.io'
    const didResolverService = agent.dependencyManager.resolve(DidResolverService)
    const didResolver = new Resolver({
      web: async (did: string) => didResolverService.resolve(agentContext, did),
    })

    // Setup spy methods
    const resolveSpy = vi.spyOn(Resolver.prototype, 'resolve')

    const result = await resolve(did, {
      didResolver,
      agentContext,
    })

    // Validate result
    expect(resolveSpy).toHaveBeenCalledTimes(1)
    expect(resolveSpy).toHaveBeenCalledWith(did)
    expect(result.verified).toEqual(true)
    expect(JSON.parse(JSON.stringify(result.didDocument))).toEqual(mockDidDocumentChatbot)
  }, 10000)

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
    })

    const result = await resolve(did, {
      agentContext,
    })

    // Validate result
    expect(result).toHaveProperty('didDocument')
    expect(result).toEqual(
      expect.objectContaining({
        didDocument: integrationDidDoc,
        verified: true,
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
  }, 10000)
})
