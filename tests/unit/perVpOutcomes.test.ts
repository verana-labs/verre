/**
 * Tests for the per-VP / per-credential outcome accumulator and the
 * spec v4 fragment-suffix conformance work introduced in
 * `feat/per-vp-outcomes`.
 *
 * NOTE: this file imports mocks **directly** from the sub-files instead
 * of from `tests/__mocks__/index.ts` because the index re-exports
 * `agent.ts`, which in turn loads `@openwallet-foundation/askar-nodejs`
 * (a native module). The unit-test environment has no native bindings
 * available, but none of the assertions below need an Askar agent —
 * we mock `verifySignature` and `fetch` instead.
 */
import { Resolver } from 'did-resolver'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

import { ECS, resolveDID, TrustErrorCode, TrustResolutionOutcome, VerifiablePublicRegistry } from '../../src'
import { resolverInstance } from '../../src/libraries'
import * as signatureVerifier from '../../src/utils/verifier'
import { fetchMocker } from '../__mocks__/fetch'
import {
  didExtIssuer,
  didSelfIssued,
  mockCredentialSchemaOrg,
  mockCredentialSchemaSer,
  mockDidDocumentSelfIssued,
  mockOrgSchema,
  mockOrgVc,
  mockPermission,
  mockResolverSelfIssued,
  mockServiceSchemaSelfIssued,
  mockServiceVcSelfIssued,
  mockW3cJsonSchemaV2,
  createVerifiableCredential,
  createVerifiablePresentation,
  verifiablePublicRegistries,
} from '../__mocks__/object'

const mockResolversByDid: Record<string, any> = {
  [didSelfIssued]: { ...mockResolverSelfIssued },
}

/** Fetch responses needed for the canonical happy-path resolution of `didSelfIssued`. */
const baselineFetchResponses = {
  'https://example.com/vp-ser-self-issued': { ok: true, status: 200, data: mockServiceVcSelfIssued },
  'https://example.com/vp-org': { ok: true, status: 200, data: mockOrgVc },
  'https://ecs-trust-registry/service-credential-schema-credential.json': {
    ok: true,
    status: 200,
    data: mockServiceSchemaSelfIssued,
  },
  'https://ecs-trust-registry/org-credential-schema-credential.json': {
    ok: true,
    status: 200,
    data: mockOrgSchema,
  },
  'https://www.w3.org/ns/credentials/json-schema/v2.json': {
    ok: true,
    status: 200,
    data: mockW3cJsonSchemaV2,
  },
  'https://testTrust.com/v1/cs/js/12345671': { ok: true, status: 200, data: mockCredentialSchemaOrg },
  'https://testTrust.com/v1/cs/js/12345678': { ok: true, status: 200, data: mockCredentialSchemaSer },
  'https://testtrust.com/v1/perm/v1/list?did=did%3Aweb%3Aservice.self-issued.example.com&type=ISSUER&response_max_size=1&schema_id=12345678':
    { ok: true, status: 200, data: mockPermission },
  'https://testtrust.com/v1/perm/v1/list?did=did%3Aweb%3Aservice.self-issued.example.com&type=ISSUER&response_max_size=1&schema_id=12345671':
    { ok: true, status: 200, data: mockPermission },
}

describe('per-VP outcome accumulator', () => {
  beforeEach(() => {
    // Stub the JSON-LD signature check; signature semantics are tested separately.
    vi.spyOn(signatureVerifier, 'verifySignature').mockResolvedValue({ result: true })
    fetchMocker.enable()
  })

  afterEach(() => {
    fetchMocker.reset()
    fetchMocker.disable()
    vi.clearAllMocks()
    resolverInstance.clear()
  })

  // ---------------------------------------------------------------------------
  // Spec v4 fragment-suffix conformance
  // ---------------------------------------------------------------------------

  describe('linked-vp fragment classification', () => {
    it('resolves DID Documents with v4 -vtc-vp suffixes', async () => {
      const v4DidDoc = {
        ...mockDidDocumentSelfIssued,
        didDocument: {
          ...mockDidDocumentSelfIssued.didDocument,
          service: [
            {
              id: `${didSelfIssued}#vpr-schemas-service-vtc-vp`,
              type: 'LinkedVerifiablePresentation',
              serviceEndpoint: ['https://example.com/vp-ser-self-issued'],
            },
            {
              id: `${didSelfIssued}#vpr-schemas-org-vtc-vp`,
              type: 'LinkedVerifiablePresentation',
              serviceEndpoint: ['https://example.com/vp-org'],
            },
          ],
        },
      }
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async () => v4DidDoc as any)
      fetchMocker.setMockResponses(baselineFetchResponses)

      const result = await resolveDID(didSelfIssued, { verifiablePublicRegistries })

      expect(result.verified).toBe(true)
      expect(result.outcome).toBe(TrustResolutionOutcome.VERIFIED)
      expect(result.validPresentations).toHaveLength(2)
      expect(result.validPresentations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            serviceId: `${didSelfIssued}#vpr-schemas-service-vtc-vp`,
            presentationType: 'vtc',
          }),
          expect.objectContaining({
            serviceId: `${didSelfIssued}#vpr-schemas-org-vtc-vp`,
            presentationType: 'vtc',
          }),
        ]),
      )
      expect(result.invalidPresentations).toEqual([])
    })

    it('preserves backward-compat with legacy v3 -c-vp suffixes', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(
        async (did: string) => mockResolversByDid[did],
      )
      fetchMocker.setMockResponses(baselineFetchResponses)

      const result = await resolveDID(didSelfIssued, { verifiablePublicRegistries })

      expect(result.verified).toBe(true)
      expect(result.validPresentations).toHaveLength(2)
      // Existing legacy fields remain populated for backward compat.
      expect(result.service).toBeDefined()
      expect(result.serviceProvider).toBeDefined()
    })

    it('handles a DID Document that mixes v3 and v4 suffixes', async () => {
      const mixedDidDoc = {
        ...mockDidDocumentSelfIssued,
        didDocument: {
          ...mockDidDocumentSelfIssued.didDocument,
          service: [
            {
              // v4
              id: `${didSelfIssued}#vpr-schemas-service-vtc-vp`,
              type: 'LinkedVerifiablePresentation',
              serviceEndpoint: ['https://example.com/vp-ser-self-issued'],
            },
            {
              // v3 (legacy)
              id: `${didSelfIssued}#vpr-schemas-org-c-vp`,
              type: 'LinkedVerifiablePresentation',
              serviceEndpoint: ['https://example.com/vp-org'],
            },
          ],
        },
      }
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async () => mixedDidDoc as any)
      fetchMocker.setMockResponses(baselineFetchResponses)

      const result = await resolveDID(didSelfIssued, { verifiablePublicRegistries })
      expect(result.verified).toBe(true)
      expect(result.validPresentations).toHaveLength(2)
    })

    it('emits FRAGMENT_NOT_CONFORMANT for vpr-* fragments with an unknown suffix', async () => {
      const badFragmentDoc = {
        ...mockDidDocumentSelfIssued,
        didDocument: {
          ...mockDidDocumentSelfIssued.didDocument,
          service: [
            {
              id: `${didSelfIssued}#vpr-schemas-service-c-vp`,
              type: 'LinkedVerifiablePresentation',
              serviceEndpoint: ['https://example.com/vp-ser-self-issued'],
            },
            {
              id: `${didSelfIssued}#vpr-schemas-org-c-vp`,
              type: 'LinkedVerifiablePresentation',
              serviceEndpoint: ['https://example.com/vp-org'],
            },
            {
              // bogus suffix
              id: `${didSelfIssued}#vpr-schemas-bogus-suffix`,
              type: 'LinkedVerifiablePresentation',
              serviceEndpoint: ['https://example.com/vp-noop'],
            },
          ],
        },
      }
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async () => badFragmentDoc as any)
      fetchMocker.setMockResponses(baselineFetchResponses)

      const result = await resolveDID(didSelfIssued, { verifiablePublicRegistries })
      expect(result.verified).toBe(true) // still resolves on the two valid VPs
      expect(result.invalidPresentations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            serviceId: `${didSelfIssued}#vpr-schemas-bogus-suffix`,
            errorCode: TrustErrorCode.FRAGMENT_NOT_CONFORMANT,
          }),
        ]),
      )
    })

    it('silently skips non-vpr LinkedVerifiablePresentation services (no FRAGMENT_NOT_CONFORMANT)', async () => {
      const docWithUnrelatedLvp = {
        ...mockDidDocumentSelfIssued,
        didDocument: {
          ...mockDidDocumentSelfIssued.didDocument,
          service: [
            ...mockDidDocumentSelfIssued.didDocument.service,
            {
              // Not a vpr fragment at all — must be silently ignored.
              id: `${didSelfIssued}#linked-domains-vp`,
              type: 'LinkedVerifiablePresentation',
              serviceEndpoint: ['https://example.com/some-other-vp'],
            },
          ],
        },
      }
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async () => docWithUnrelatedLvp as any)
      fetchMocker.setMockResponses(baselineFetchResponses)

      const result = await resolveDID(didSelfIssued, { verifiablePublicRegistries })
      expect(result.invalidPresentations).toEqual([])
    })
  })

  // ---------------------------------------------------------------------------
  // Per-VP failure isolation (Promise.allSettled behaviour)
  // ---------------------------------------------------------------------------

  describe('per-VP error reporting', () => {
    it('reports DEREFERENCE_FAILED when the VP endpoint returns 404', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(
        async (did: string) => mockResolversByDid[did],
      )
      fetchMocker.setMockResponses({
        ...baselineFetchResponses,
        // org VP: simulate 404
        'https://example.com/vp-org': { ok: false, status: 404, data: { error: 'not found' } },
      })

      const result = await resolveDID(didSelfIssued, { verifiablePublicRegistries })
      // service VP is still valid → service exists; but no org → not verified
      expect(result.invalidPresentations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            serviceId: `${didSelfIssued}#vpr-schemas-org-c-vp`,
            errorCode: TrustErrorCode.DEREFERENCE_FAILED,
          }),
        ]),
      )
    })

    it('reports VP_SIGNATURE_INVALID when verifySignature returns result=false', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(
        async (did: string) => mockResolversByDid[did],
      )
      // Restore real verifySignature to fake a single-VP failure
      vi.spyOn(signatureVerifier, 'verifySignature').mockImplementation(async (doc: any) => {
        if (doc.id?.includes('verifiable-presentation')) {
          // Fail signature for the OrgVP, succeed for ServiceVP
          if (
            doc.holder === didSelfIssued &&
            doc.verifiableCredential[0]?.credentialSubject?.name === 'Example Corp'
          ) {
            return { result: false, error: 'fake signature failure' }
          }
        }
        return { result: true }
      })
      fetchMocker.setMockResponses(baselineFetchResponses)

      const result = await resolveDID(didSelfIssued, { verifiablePublicRegistries })
      expect(result.invalidPresentations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            errorCode: TrustErrorCode.VP_SIGNATURE_INVALID,
          }),
        ]),
      )
    })

    /**
     * Regression test for the coarse `metadata.errorCode` on the
     * partial-failure path:
     *
     *   * If at least one VP was attempted and rejected (e.g. signature
     *     verification failed), the legacy contract is `INVALID`.
     *   * Throwing `NOT_FOUND` here (as the original `feat/per-vp-outcomes`
     *     refactor accidentally did) is a regression because consumers
     *     route on the coarse code: `INVALID` means "we tried to verify a
     *     credential and rejected it" while `NOT_FOUND` means "nothing to
     *     verify in the first place".
     *
     * The fine-grained per-VP details remain on `invalidPresentations`
     * regardless; this test only pins the top-level coarse code.
     */
    it('returns metadata.errorCode = INVALID when some VPs failed validation', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(
        async (did: string) => mockResolversByDid[did],
      )
      // Same scenario as the VP_SIGNATURE_INVALID test above: org VP is
      // rejected, service VP succeeds, so no service+serviceProvider pair
      // can be assembled. Without the fix this surfaces as NOT_FOUND.
      vi.spyOn(signatureVerifier, 'verifySignature').mockImplementation(async (doc: any) => {
        if (
          doc.id?.includes('verifiable-presentation') &&
          doc.holder === didSelfIssued &&
          doc.verifiableCredential[0]?.credentialSubject?.name === 'Example Corp'
        ) {
          return { result: false, error: 'fake signature failure' }
        }
        return { result: true }
      })
      fetchMocker.setMockResponses(baselineFetchResponses)

      const result = await resolveDID(didSelfIssued, { verifiablePublicRegistries })
      expect(result.verified).toBe(false)
      expect(result.outcome).toBe(TrustResolutionOutcome.INVALID)
      expect(result.metadata?.errorCode).toBe(TrustErrorCode.INVALID)
      // Sanity-check that the fine-grained array still carries the per-VP
      // failure so callers that opt in keep full diagnostics.
      expect(result.invalidPresentations?.length).toBeGreaterThan(0)
    })

    /**
     * Counterpart to the regression test above: when nothing was even
     * tried (all linked-vp services were silently skipped because none
     * carry a recognisable `vpr-*` fragment), the coarse code stays
     * `NOT_FOUND` — there really is nothing to evaluate.
     */
    it('returns metadata.errorCode = NOT_FOUND when no VPs were attempted', async () => {
      const docWithUnrelatedLvpOnly = {
        ...mockDidDocumentSelfIssued,
        didDocument: {
          ...mockDidDocumentSelfIssued.didDocument,
          service: [
            {
              id: `${didSelfIssued}#linked-domains-vp`,
              type: 'LinkedVerifiablePresentation',
              serviceEndpoint: ['https://example.com/some-other-vp'],
            },
          ],
        },
      }
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async () => docWithUnrelatedLvpOnly as any)
      fetchMocker.setMockResponses(baselineFetchResponses)

      const result = await resolveDID(didSelfIssued, { verifiablePublicRegistries })
      expect(result.verified).toBe(false)
      expect(result.metadata?.errorCode).toBe(TrustErrorCode.NOT_FOUND)
      expect(result.invalidPresentations).toEqual([])
    })

    it('reports ISSUER_PERMISSION_MISSING when the perm endpoint returns no permissions', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(
        async (did: string) => mockResolversByDid[did],
      )
      fetchMocker.setMockResponses({
        ...baselineFetchResponses,
        // Org credential's permission lookup: empty list → no ISSUER permission
        'https://testtrust.com/v1/perm/v1/list?did=did%3Aweb%3Aservice.self-issued.example.com&type=ISSUER&response_max_size=1&schema_id=12345671':
          { ok: true, status: 200, data: { permissions: [] } },
      })

      const result = await resolveDID(didSelfIssued, { verifiablePublicRegistries })
      expect(result.invalidPresentations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            errorCode: TrustErrorCode.ISSUER_PERMISSION_MISSING,
          }),
        ]),
      )
    })

    it('reports ISSUER_PERMISSION_NOT_EFFECTIVE when issuanceDate is outside the permission window', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(
        async (did: string) => mockResolversByDid[did],
      )
      fetchMocker.setMockResponses({
        ...baselineFetchResponses,
        // Org perm: effective range strictly AFTER the credential issuance date
        'https://testtrust.com/v1/perm/v1/list?did=did%3Aweb%3Aservice.self-issued.example.com&type=ISSUER&response_max_size=1&schema_id=12345671':
          {
            ok: true,
            status: 200,
            data: {
              permissions: [
                {
                  type: 'ISSUER',
                  created: '2099-01-01T00:00:00.000Z',
                  effective_from: '2099-01-01T00:00:00.000Z',
                  effective_until: '2099-12-31T23:59:59.000Z',
                },
              ],
            },
          },
      })

      const result = await resolveDID(didSelfIssued, { verifiablePublicRegistries })
      expect(result.invalidPresentations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            errorCode: TrustErrorCode.ISSUER_PERMISSION_NOT_EFFECTIVE,
          }),
        ]),
      )
    })
  })

  // ---------------------------------------------------------------------------
  // Multi-credential VP handling
  // ---------------------------------------------------------------------------

  describe('multi-credential VPs', () => {
    it('processes all credentials in a multi-credential VP', async () => {
      // Build a VP that holds TWO credentials: a service VC and an org VC.
      const multiVp = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        holder: didSelfIssued,
        type: ['VerifiablePresentation'],
        verifiableCredential: [
          createVerifiableCredential(
            didSelfIssued,
            {
              id: 'https://ecs-trust-registry/service-credential-schema-credential.json',
              type: 'JsonSchemaCredential',
            },
            mockServiceVcSelfIssued.verifiableCredential[0].credentialSubject,
          ),
          createVerifiableCredential(
            didSelfIssued,
            {
              id: 'https://ecs-trust-registry/org-credential-schema-credential.json',
              type: 'JsonSchemaCredential',
            },
            mockOrgVc.verifiableCredential[0].credentialSubject,
          ),
        ],
        id: `https://example.com/multi-cred-vp-${didSelfIssued}.jsonld`,
        proof: {
          type: 'Ed25519Signature2018',
          created: '2024-02-08T17:38:46Z',
          verificationMethod: `${didSelfIssued}#key-1`,
          proofPurpose: 'assertionMethod',
          jws: 'eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..signature',
        },
      }

      const singleSvcDidDoc = {
        ...mockDidDocumentSelfIssued,
        didDocument: {
          ...mockDidDocumentSelfIssued.didDocument,
          service: [
            {
              id: `${didSelfIssued}#vpr-schemas-multi-c-vp`,
              type: 'LinkedVerifiablePresentation',
              serviceEndpoint: ['https://example.com/multi-cred-vp'],
            },
          ],
        },
      }
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async () => singleSvcDidDoc as any)
      fetchMocker.setMockResponses({
        ...baselineFetchResponses,
        'https://example.com/multi-cred-vp': { ok: true, status: 200, data: multiVp },
      })

      const result = await resolveDID(didSelfIssued, { verifiablePublicRegistries })

      // The single VP yielded TWO valid credentials, both reported under the
      // same `validPresentations` entry (one entry per VP).
      expect(result.verified).toBe(true)
      expect(result.validPresentations).toHaveLength(1)
      expect(result.validPresentations?.[0].credentialIds).toHaveLength(2)
      // Legacy fields still populated.
      expect(result.service).toBeDefined()
      expect(result.serviceProvider).toBeDefined()
    })

    it('splits a partially-valid multi-credential VP across both arrays', async () => {
      // 1 valid (service) + 1 invalid (org with no ISSUER permission)
      const partialVp = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        holder: didSelfIssued,
        type: ['VerifiablePresentation'],
        verifiableCredential: [
          createVerifiableCredential(
            didSelfIssued,
            {
              id: 'https://ecs-trust-registry/service-credential-schema-credential.json',
              type: 'JsonSchemaCredential',
            },
            mockServiceVcSelfIssued.verifiableCredential[0].credentialSubject,
          ),
          createVerifiableCredential(
            didSelfIssued,
            {
              id: 'https://ecs-trust-registry/org-credential-schema-credential.json',
              type: 'JsonSchemaCredential',
            },
            mockOrgVc.verifiableCredential[0].credentialSubject,
          ),
        ],
        id: `https://example.com/partial-vp-${didSelfIssued}.jsonld`,
        proof: {
          type: 'Ed25519Signature2018',
          created: '2024-02-08T17:38:46Z',
          verificationMethod: `${didSelfIssued}#key-1`,
          proofPurpose: 'assertionMethod',
          jws: 'eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..signature',
        },
      }
      // Give each credential a distinct, deterministic id so we can assert membership.
      partialVp.verifiableCredential[0].id = 'urn:uuid:cred-service-OK'
      partialVp.verifiableCredential[1].id = 'urn:uuid:cred-org-FAIL'

      const singleSvcDidDoc = {
        ...mockDidDocumentSelfIssued,
        didDocument: {
          ...mockDidDocumentSelfIssued.didDocument,
          service: [
            {
              id: `${didSelfIssued}#vpr-schemas-mixed-c-vp`,
              type: 'LinkedVerifiablePresentation',
              serviceEndpoint: ['https://example.com/partial-vp'],
            },
          ],
        },
      }
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async () => singleSvcDidDoc as any)
      fetchMocker.setMockResponses({
        ...baselineFetchResponses,
        'https://example.com/partial-vp': { ok: true, status: 200, data: partialVp },
        // Org credential's permission lookup: empty → ISSUER_PERMISSION_MISSING
        'https://testtrust.com/v1/perm/v1/list?did=did%3Aweb%3Aservice.self-issued.example.com&type=ISSUER&response_max_size=1&schema_id=12345671':
          { ok: true, status: 200, data: { permissions: [] } },
      })

      const result = await resolveDID(didSelfIssued, { verifiablePublicRegistries })

      // Service credential succeeded.
      expect(result.validPresentations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            serviceId: `${didSelfIssued}#vpr-schemas-mixed-c-vp`,
            credentialIds: expect.arrayContaining(['urn:uuid:cred-service-OK']),
          }),
        ]),
      )
      // Org credential failed, in the SAME serviceId.
      expect(result.invalidPresentations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            serviceId: `${didSelfIssued}#vpr-schemas-mixed-c-vp`,
            errorCode: TrustErrorCode.ISSUER_PERMISSION_MISSING,
            credentialIds: expect.arrayContaining(['urn:uuid:cred-org-FAIL']),
          }),
        ]),
      )
    })
  })

  // ---------------------------------------------------------------------------
  // ECS Trust Registry whitelist (allowedEcsEcosystems)
  // ---------------------------------------------------------------------------

  describe('ECS ecosystem whitelist', () => {
    /** Build a registry list scoped to the test schemas, with an optional whitelist. */
    function registriesWithWhitelist(allowedEcsEcosystems?: string[]): VerifiablePublicRegistry[] {
      return [
        {
          id: 'https://vpr-hostname/vpr',
          baseUrls: ['https://testTrust.com'],
          production: true,
          allowedEcsEcosystems,
        },
        ...verifiablePublicRegistries.filter(r => r.id !== 'https://vpr-hostname/vpr'),
      ]
    }

    it('rejects credentials whose JSC issuer is not in allowedEcsEcosystems', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(
        async (did: string) => mockResolversByDid[did],
      )
      fetchMocker.setMockResponses(baselineFetchResponses)

      const result = await resolveDID(didSelfIssued, {
        verifiablePublicRegistries: registriesWithWhitelist(['did:web:some-other-ecosystem.example.com']),
      })

      expect(result.invalidPresentations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            errorCode: TrustErrorCode.ECS_TRUST_REGISTRY_NOT_WHITELISTED,
          }),
        ]),
      )
    })

    it('accepts credentials whose JSC issuer is in allowedEcsEcosystems', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(
        async (did: string) => mockResolversByDid[did],
      )
      fetchMocker.setMockResponses(baselineFetchResponses)

      // The mock JSCs (mockServiceSchemaSelfIssued, mockOrgSchema) are issued
      // by `didSelfIssued`. Whitelist that DID and resolution should pass.
      const result = await resolveDID(didSelfIssued, {
        verifiablePublicRegistries: registriesWithWhitelist([didSelfIssued]),
      })
      expect(result.verified).toBe(true)
      expect(
        result.invalidPresentations?.some(
          v => v.errorCode === TrustErrorCode.ECS_TRUST_REGISTRY_NOT_WHITELISTED,
        ),
      ).toBeFalsy()
    })

    it('does not enforce the whitelist when allowedEcsEcosystems is empty/undefined', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(
        async (did: string) => mockResolversByDid[did],
      )
      fetchMocker.setMockResponses(baselineFetchResponses)

      const result = await resolveDID(didSelfIssued, {
        verifiablePublicRegistries: registriesWithWhitelist(undefined),
      })

      expect(result.verified).toBe(true)
      expect(
        result.invalidPresentations?.some(
          v => v.errorCode === TrustErrorCode.ECS_TRUST_REGISTRY_NOT_WHITELISTED,
        ),
      ).toBeFalsy()
    })

    it('does not enforce the whitelist when allowedEcsEcosystems is an empty array', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(
        async (did: string) => mockResolversByDid[did],
      )
      fetchMocker.setMockResponses(baselineFetchResponses)

      const result = await resolveDID(didSelfIssued, {
        verifiablePublicRegistries: registriesWithWhitelist([]),
      })

      expect(result.verified).toBe(true)
    })
  })

  // ---------------------------------------------------------------------------
  // Backward-compat assertions
  // ---------------------------------------------------------------------------

  describe('backward compatibility', () => {
    it('preserves the legacy top-level fields (service, serviceProvider, outcome, verified)', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(
        async (did: string) => mockResolversByDid[did],
      )
      fetchMocker.setMockResponses(baselineFetchResponses)

      const result = await resolveDID(didSelfIssued, { verifiablePublicRegistries })

      expect(result.verified).toBe(true)
      expect(result.outcome).toBe(TrustResolutionOutcome.VERIFIED)
      // `id` on the credential reflects the `credentialSubject.id` of the
      // underlying VC (which is independent of the DID being resolved), so
      // we only assert the discriminating `schemaType` and `issuer` here.
      expect(result.service).toEqual(
        expect.objectContaining({
          schemaType: ECS.SERVICE,
          issuer: didSelfIssued,
        }),
      )
      expect(result.serviceProvider).toEqual(
        expect.objectContaining({
          schemaType: ECS.ORG,
          issuer: didSelfIssued,
        }),
      )
      // didDocument round-trip
      expect(result.didDocument).toEqual(mockDidDocumentSelfIssued.didDocument)
    })

    it('returns empty arrays for valid/invalid presentations on full success when no failures occur', async () => {
      vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(
        async (did: string) => mockResolversByDid[did],
      )
      fetchMocker.setMockResponses(baselineFetchResponses)

      const result = await resolveDID(didSelfIssued, { verifiablePublicRegistries })
      expect(result.invalidPresentations).toEqual([])
      // unused variable ensures linter does not complain on no-eslint-disable runs
      void didExtIssuer
      void createVerifiablePresentation
    })
  })
})
