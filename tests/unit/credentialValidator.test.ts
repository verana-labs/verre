import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

import { ParticipantRole, resolveCredential, TrustResolutionOutcome, verifyParticipant } from '../../src'
import * as signatureVerifier from '../../src/utils/verifier'
import {
  fetchMocker,
  verifiablePublicRegistries,
  jscCredentialService,
  jsCredentialService,
  ecsService,
  mockParticipant,
  mockW3cJsonSchemaV2,
  mockHolderParticipant,
} from '../__mocks__'

describe('Credential Validator', () => {
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
    })

    it('should work correctly when the issuer is equal to "did" over testing network.', async () => {
      // mocked data
      fetchMocker.setMockResponses({
        'https://d6a1950112a2.ngrok-free.app/vt/schemas-example-service-jsc.json': {
          ok: true,
          status: 200,
          data: jsCredentialService,
        },
        'https://www.w3.org/ns/credentials/json-schema/v2.json': {
          ok: true,
          status: 200,
          data: mockW3cJsonSchemaV2,
        },
        'https://d6a1950112a2.ngrok-free.app/vt/cs/v1/js/ecs-service': {
          ok: true,
          status: 200,
          data: ecsService,
        },
        'https://d6a1950112a2.ngrok-free.app/v4/participant/list?did=did%3Aweb%3Ad6a1950112a2.ngrok-free.app&role=ISSUER&limit=1&schema_id=ecs-service':
          {
            ok: true,
            status: 200,
            data: mockParticipant,
          },
      })

      // Execute method under test
      const result = await resolveCredential(jscCredentialService, {
        verifiablePublicRegistries,
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
        'https://www.w3.org/ns/credentials/json-schema/v2.json': {
          ok: true,
          status: 200,
          data: mockW3cJsonSchemaV2,
        },
        'https://d6a1950112a2.ngrok-free.app/vt/cs/v1/js/ecs-service': {
          ok: true,
          status: 200,
          data: ecsService,
        },
        'https://d6a1950112a2.ngrok-free.app/v4/participant/list?did=did%3Aweb%3Ad6a1950112a2.ngrok-free.app&role=HOLDER&limit=1&schema_id=ecs-service':
          {
            ok: true,
            status: 200,
            data: mockHolderParticipant,
          },
      })

      const result = await verifyParticipant({
        did: 'did:web:d6a1950112a2.ngrok-free.app',
        jsonSchemaCredentialId: 'https://d6a1950112a2.ngrok-free.app/vt/schemas-example-service-jsc.json',
        issuanceDate: '2025-11-20T00:22:56.885Z',
        verifiablePublicRegistries,
        role: ParticipantRole.HOLDER,
      })
      expect(result.verified).toBe(true)
    })
  })
})
