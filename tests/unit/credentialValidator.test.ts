import { Agent, AgentContext } from '@credo-ts/core'
import { Resolver } from 'did-resolver'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

import { resolveCredential, TrustResolutionOutcome } from '../../src'
import * as signatureVerifier from '../../src/utils/verifier'
import {
  fetchMocker,
  setupAgent,
  verifiablePublicRegistries,
  jscCredentialService,
  credentialDid,
  mockResolverCredentialDid,
  jsCredentialService,
  ecsService,
  mockPermission,
} from '../__mocks__'

const mockResolversByDid: Record<string, any> = {
  [credentialDid]: mockResolverCredentialDid,
}

describe('Credential Validator', () => {
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
        'https://d6a1950112a2.ngrok-free.app/vt/schemas-example-service-jsc.json': {
          ok: true,
          status: 200,
          data: jsCredentialService,
        },
        'https://d6a1950112a2.ngrok-free.app/vt/cs/v1/js/ecs-service': {
          ok: true,
          status: 200,
          data: ecsService,
        },
        'https://d6a1950112a2.ngrok-free.app/vt/perm/v1/list?did=did%3Aweb%3Ad6a1950112a2.ngrok-free.app&type=ISSUER&response_max_size=1&schema_id=ecs-service':
          {
            ok: true,
            status: 200,
            data: mockPermission,
          },
      })

      // Execute method under test
      const result = await resolveCredential(jscCredentialService, {
        verifiablePublicRegistries,
        agentContext,
      })
      expect(resolverInstanceSpy).toHaveBeenCalledWith(credentialDid)
      expect(result.verified).toBe(true)
      expect(result.outcome).toBe(TrustResolutionOutcome.NOT_TRUSTED)
      expect(resolverInstanceSpy).toHaveBeenCalledTimes(1)
    })
  })
})
