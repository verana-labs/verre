import { Resolver } from 'did-resolver'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ECS, resolveDID, TrustErrorCode, TrustResolutionOutcome } from '../../src'
import { resolverInstance } from '../../src/libraries'
import { computeCredentialDigestJCS } from '../../src/utils/credentialDigest'
import { clearSchemaCache } from '../../src/utils/helper'
import {
  ecosystemDid,
  ecosystemResolver,
  fetchMocker,
  mockCredentialSchemaOrg,
  mockCredentialSchemaSer,
  mockOrgSchema,
  mockParticipant,
  mockServiceSchemaSelfIssued,
  mockW3cJsonSchemaV2,
  signSchemaCredential,
  vcdm2Did,
  vcdm2OrgVp,
  vcdm2Resolver,
  vcdm2ServiceVp,
  verifiablePublicRegistries,
} from '../__mocks__'

// The trust resolution of a DID whose linked VPs carry VC Data Model 2.0 credentials secured with
// DataIntegrityProof (eddsa-jcs-2022): real signature verification, of the schema credentials too
// ([TR-3]), ledger evidence mocked.
const IDX = 'https://idx.testnet.verana.network'
const ANCHORED_AT = '2024-02-08T18:38:46+01:00'
const SCHEMA_IDS = { service: 12345678, org: 12345671 }
const SERVICE_VP_URL = 'https://vcdm2.example/vt/vpr-schemas-service-vtc-vp.json'
const ORG_VP_URL = 'https://vcdm2.example/vt/vpr-schemas-org-vtc-vp.json'

const serviceVc = vcdm2ServiceVp.verifiableCredential[0]
const orgVc = vcdm2OrgVp.verifiableCredential[0]

const ok = (data: unknown) => ({ ok: true, status: 200, data })
const participantsUrl = (role: string, schemaId: number) =>
  `${IDX}/v4/participant/list?did=${encodeURIComponent(vcdm2Did)}&role=${role}&schema_id=${schemaId}&when=${encodeURIComponent(ANCHORED_AT)}`

const mockResponses = () => {
  const responses: Record<string, ReturnType<typeof ok>> = {
    [SERVICE_VP_URL]: ok(vcdm2ServiceVp),
    [ORG_VP_URL]: ok(vcdm2OrgVp),
    'https://ecs-trust-registry/service-credential-schema-credential.json': ok(
      signSchemaCredential(mockServiceSchemaSelfIssued),
    ),
    'https://ecs-trust-registry/org-credential-schema-credential.json': ok(
      signSchemaCredential(mockOrgSchema),
    ),
    'https://www.w3.org/ns/credentials/json-schema/v2.json': ok(mockW3cJsonSchemaV2),
    [`${IDX}/v4/credential-schema/js/${SCHEMA_IDS.service}`]: ok(mockCredentialSchemaSer),
    [`${IDX}/v4/credential-schema/js/${SCHEMA_IDS.org}`]: ok(mockCredentialSchemaOrg),
  }
  for (const id of Object.values(SCHEMA_IDS)) {
    responses[`${IDX}/v4/credential-schema/get/${id}`] = ok({
      schema: { id, ecosystem_id: 1, digest_algorithm: 'sha384', json_schema: '' },
    })
    responses[participantsUrl('ISSUER', id)] = ok(mockParticipant)
    responses[participantsUrl('HOLDER', id)] = ok({ participants: [] })
  }
  // [IDX-VT-EVAL-1] the digest of the credential as published is what the ledger anchored
  for (const vc of [serviceVc, orgVc]) {
    const digest = computeCredentialDigestJCS(vc, 'sha384')
    responses[`${IDX}/v4/di/get/${encodeURIComponent(digest)}`] = ok({
      digest: { digest, created: ANCHORED_AT },
    })
  }
  return responses
}

const SERVICE_SCHEMA_CREDENTIAL_URL = 'https://ecs-trust-registry/service-credential-schema-credential.json'

describe('VC Data Model 2.0 trust resolution', () => {
  let resolvers: Record<string, unknown>

  beforeEach(() => {
    resolvers = {
      [vcdm2Did]: vcdm2Resolver,
      [ecosystemDid]: ecosystemResolver,
    }
    vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(
      async (did: string) =>
        (resolvers[did] as never) ?? {
          didResolutionMetadata: { error: 'notFound' },
          didDocumentMetadata: {},
          didDocument: null,
        },
    )
    fetchMocker.enable()
    fetchMocker.setMockResponses(mockResponses())
  })

  afterEach(() => {
    fetchMocker.reset()
    fetchMocker.disable()
    vi.restoreAllMocks()
    resolverInstance.clear()
    clearSchemaCache()
  })

  it('resolves a DID whose linked VPs carry Data Integrity secured 2.0 credentials', async () => {
    const result = await resolveDID(vcdm2Did, { verifiablePublicRegistries })

    expect(result.metadata).toBeUndefined()
    expect(result.verified).toBe(true)
    expect(result.outcome).toBe(TrustResolutionOutcome.VERIFIED)
    expect(result.anchorPattern).toBe('self')
    expect(result.service).toEqual(
      expect.objectContaining({
        ecs: ECS.SERVICE,
        id: serviceVc.id,
        issuer: vcdm2Did,
        subject: expect.objectContaining({ id: vcdm2Did, name: serviceVc.credentialSubject.name }),
        // validFrom / validUntil come straight from the 2.0 credential
        validFrom: serviceVc.validFrom,
        validUntil: serviceVc.validUntil,
        issuedAtTime: ANCHORED_AT,
        credentialSchemaId: SCHEMA_IDS.service,
        raw: serviceVc,
      }),
    )
    expect(result.serviceProvider).toEqual(
      expect.objectContaining({
        ecs: ECS.ORG,
        id: orgVc.id,
        issuer: vcdm2Did,
        validFrom: orgVc.validFrom,
        validUntil: orgVc.validUntil,
        raw: orgVc,
      }),
    )
    expect(result.expiresAtTime).toBe(new Date(serviceVc.validUntil).toISOString())
    expect(result.failedCredentials).toBeUndefined()
    expect(result.presentations?.map(presentation => presentation.credentials.length)).toEqual([1, 1])
  })

  it('reports the presentation as invalid when the credential it carries was altered', async () => {
    // the presentation proof covers the carried credential, so it is what fails first
    const tampered = JSON.parse(JSON.stringify(vcdm2ServiceVp)) as typeof vcdm2ServiceVp
    tampered.verifiableCredential[0].credentialSubject.name = 'Impostor'
    fetchMocker.addMockResponse(SERVICE_VP_URL, ok(tampered))

    const result = await resolveDID(vcdm2Did, { verifiablePublicRegistries })

    expect(result.verified).toBe(false)
    expect(result.outcome).toBe(TrustResolutionOutcome.INVALID)
    expect(result.metadata?.errorMessage).toContain('Ed25519 signature verification failed')
    expect(result.failedCredentials).toEqual([
      expect.objectContaining({
        id: serviceVc.id,
        errorCode: TrustErrorCode.INVALID,
        error: 'Ed25519 signature verification failed',
      }),
    ])
    const servicePresentation = result.presentations?.find(p =>
      p.serviceId.endsWith('#vpr-schemas-service-vtc-vp'),
    )
    expect(servicePresentation?.invalidCredentialIds).toEqual([serviceVc.id])
    // the untouched org credential still resolves
    expect(result.serviceProvider?.ecs).toBe(ECS.ORG)
    expect(result.service).toBeUndefined()
  })

  describe('[TR-3] the JSON Schema Credential proof', () => {
    const expectSchemaCredentialRejected = (
      result: Awaited<ReturnType<typeof resolveDID>>,
      reason: string,
    ) => {
      expect(result.verified).toBe(false)
      expect(result.outcome).toBe(TrustResolutionOutcome.INVALID)
      expect(result.failedCredentials).toEqual([
        expect.objectContaining({
          errorCode: TrustErrorCode.VERIFICATION_FAILED,
          error: `The JSON Schema Credential proof is not valid for ${SERVICE_SCHEMA_CREDENTIAL_URL}: ${reason}`,
        }),
      ])
      // the credential itself verified; its schema credential is what failed
      expect(result.presentations?.find(p => p.serviceId.endsWith('#vpr-schemas-service-vtc-vp'))).toEqual(
        expect.objectContaining({ invalidCredentialIds: [serviceVc.id] }),
      )
      // the org credential, whose schema credential is intact, still resolves
      expect(result.serviceProvider?.ecs).toBe(ECS.ORG)
      expect(result.service).toBeUndefined()
    }

    it('fails the credential when the proof of its schema credential was tampered with', async () => {
      const signed = signSchemaCredential(mockServiceSchemaSelfIssued) as { proof: { proofValue: string } }
      const proofValue = signed.proof.proofValue
      const tampered = {
        ...signed,
        proof: {
          ...signed.proof,
          proofValue: proofValue.slice(0, -1) + (proofValue.endsWith('1') ? '2' : '1'),
        },
      }
      fetchMocker.addMockResponse(SERVICE_SCHEMA_CREDENTIAL_URL, ok(tampered))

      const result = await resolveDID(vcdm2Did, { verifiablePublicRegistries })

      expectSchemaCredentialRejected(result, 'Ed25519 signature verification failed')
    })

    it('fails the credential when the schema credential content was altered after signing', async () => {
      const signed = signSchemaCredential(mockServiceSchemaSelfIssued) as {
        credentialSubject: { id: string }
      }
      const altered = {
        ...signed,
        credentialSubject: { ...signed.credentialSubject, id: 'https://evil.example/other-schema.json' },
      }
      fetchMocker.addMockResponse(SERVICE_SCHEMA_CREDENTIAL_URL, ok(altered))

      const result = await resolveDID(vcdm2Did, { verifiablePublicRegistries })

      expectSchemaCredentialRejected(result, 'Ed25519 signature verification failed')
    })

    it('fails the credential when the Ecosystem DID of its schema credential cannot be resolved', async () => {
      // the service schema credential is issued by an Ecosystem nobody can resolve
      const unresolvableEcosystem = 'did:web:gone.example'
      const signed = signSchemaCredential(mockServiceSchemaSelfIssued) as {
        proof: { verificationMethod: string }
      }
      fetchMocker.addMockResponse(
        SERVICE_SCHEMA_CREDENTIAL_URL,
        ok({
          ...signed,
          issuer: unresolvableEcosystem,
          proof: { ...signed.proof, verificationMethod: `${unresolvableEcosystem}#key-1` },
        }),
      )

      const result = await resolveDID(vcdm2Did, { verifiablePublicRegistries })

      expectSchemaCredentialRejected(
        result,
        `Cannot resolve verification method: ${unresolvableEcosystem}#key-1`,
      )
    })

    it('resolves without the Ecosystem DID when skipSchemaCredentialProofCheck is set', async () => {
      delete resolvers[ecosystemDid]

      const result = await resolveDID(vcdm2Did, {
        verifiablePublicRegistries,
        skipSchemaCredentialProofCheck: true,
      })

      expect(result.verified).toBe(true)
      expect(result.outcome).toBe(TrustResolutionOutcome.VERIFIED)
    })
  })
})
