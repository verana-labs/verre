import { Agent, AgentContext } from '@credo-ts/core'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

import { PermissionType, resolveCredential, TrustResolutionOutcome, verifyPermissions } from '../../src'
import * as signatureVerifier from '../../src/utils/verifier'
import {
  fetchMocker,
  setupAgent,
  verifiablePublicRegistries,
  jscCredentialService,
  jsCredentialService,
  ecsService,
  mockPermission,
  mockHolderPermission,
} from '../__mocks__'

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
      expect(result.verified).toBe(true)
      expect(result.outcome).toBe(TrustResolutionOutcome.NOT_TRUSTED)
    })

    it('should return verified: true when permission checks succeed', async () => {
      // mocked data
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
        'https://d6a1950112a2.ngrok-free.app/vt/perm/v1/list?did=did%3Aweb%3Ad6a1950112a2.ngrok-free.app&type=HOLDER&response_max_size=1&schema_id=ecs-service':
          {
            ok: true,
            status: 200,
            data: mockHolderPermission,
          },
      })

      const result = await verifyPermissions({
        did: 'did:web:d6a1950112a2.ngrok-free.app',
        jsonSchemaCredentialId: 'https://d6a1950112a2.ngrok-free.app/vt/schemas-example-service-jsc.json',
        issuanceDate: '2025-11-20T00:22:56.885Z',
        verifiablePublicRegistries,
        permissionType: PermissionType.HOLDER,
      })
      expect(result.verified).toBe(true)
    })
  })
})
