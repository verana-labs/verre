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
} from '../__mocks__'

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

  it('should integrate with Verana testnet and retrieve the nested schema from the blockchain', async () => {
    const did = 'did:web:bcccdd780017.ngrok-free.app'

    // Create a mock object representing a didDocument
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
  }, 20000)
})
