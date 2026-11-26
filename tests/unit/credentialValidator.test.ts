import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

import { ParticipantRole, resolveCredential, TrustResolutionOutcome, verifyParticipant } from '../../src'
import { clearSchemaCache } from '../../src/utils/helper'
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
  mockServiceSchemaSelfIssued,
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
      clearSchemaCache()
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

    describe('[TR-3] the JSON Schema Credential proof', () => {
      const IDX = 'https://idx.testnet.verana.network'
      const options = {
        did: 'did:web:issuer.example',
        jsonSchemaCredentialId: 'https://ecs-trust-registry/service-credential-schema-credential.json',
        issuanceDate: '2024-02-08T18:38:46+01:00',
        verifiablePublicRegistries,
        role: ParticipantRole.ISSUER,
      }
      const participantsUrl = `${IDX}/v4/participant/list?did=${encodeURIComponent(options.did)}&role=ISSUER&schema_id=12345678&when=${encodeURIComponent(options.issuanceDate)}`
      const requestedParticipants = () =>
        (global.fetch as unknown as { mock: { calls: string[][] } }).mock.calls
          .map(c => c[0])
          .some(url => url.includes('/v4/participant/list'))

      beforeEach(() => {
        fetchMocker.setMockResponses({
          [options.jsonSchemaCredentialId]: { ok: true, status: 200, data: mockServiceSchemaSelfIssued },
          [participantsUrl]: { ok: true, status: 200, data: mockParticipant },
        })
      })

      it('is verified before the Participant is looked up', async () => {
        const result = await verifyParticipant(options)

        expect(result.verified).toBe(true)
        expect(signatureVerifier.verifySignature).toHaveBeenCalledWith(
          expect.objectContaining({ id: mockServiceSchemaSelfIssued.id }),
          expect.anything(),
          expect.anything(),
        )
        expect(requestedParticipants()).toBe(true)
      })

      it('fails the verification when the proof is not valid, without looking the Participant up', async () => {
        vi.mocked(signatureVerifier.verifySignature).mockResolvedValue({
          result: false,
          error: 'Ed25519 signature verification failed',
        })

        const result = await verifyParticipant(options)

        expect(result.verified).toBe(false)
        expect(requestedParticipants()).toBe(false)
      })

      it('is skipped with skipSchemaCredentialProofCheck', async () => {
        const result = await verifyParticipant({ ...options, skipSchemaCredentialProofCheck: true })

        expect(result.verified).toBe(true)
        expect(signatureVerifier.verifySignature).not.toHaveBeenCalled()
      })
    })
  })
})
