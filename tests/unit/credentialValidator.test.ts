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
        'https://d6a1950112a2.ngrok-free.app/v4/participant/list?did=did%3Aweb%3Ad6a1950112a2.ngrok-free.app&role=ISSUER&schema_id=ecs-service&when=2025-11-19T15%3A52%3A45.519Z':
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

    it('cannot verify a Participant for a schema outside a registry', async () => {
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
        'https://d6a1950112a2.ngrok-free.app/v4/participant/list?did=did%3Aweb%3Ad6a1950112a2.ngrok-free.app&role=HOLDER&schema_id=ecs-service&when=2025-11-20T00%3A22%3A56.885Z':
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
      expect(result.verified).toBe(false)
      const requested = (global.fetch as unknown as { mock: { calls: string[][] } }).mock.calls.map(c => c[0])
      expect(requested.some(url => url.includes('/v4/participant/list'))).toBe(false)
    })
  })
})
