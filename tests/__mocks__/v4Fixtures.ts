// Dynamic v4 fixtures: a did:web agent generated and signed at test setup, so the
// integration suite keeps positive trusted-path coverage that tracks the published schemas.

import {
  Agent,
  AgentContext,
  DidDocument,
  DidResolverService,
  JsonTransformer,
  Kms,
  W3cCredential,
  W3cCredentialsModuleConfig,
  W3cJsonLdVerifiableCredential,
  W3cJsonLdVerifiablePresentation,
  W3cPresentation,
  ClaimFormat,
  vcLibraries,
} from '@credo-ts/core'
import { createHash } from 'crypto'
import { vi } from 'vitest'

import { computeCredentialDigestJCS } from '../../src/utils/credentialDigest'

import { essentialSchemas } from './data'
import { mockParticipant } from './object'

// Vendored copy of https://www.w3.org/ns/credentials/json-schema/v2.json so tests stay offline
const jsonSchemaCredentialMetaSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://www.w3.org/2022/credentials/v2/json-schema-credential-schema.json',
  description:
    'JSON Schema for a Verifiable Credential of type JsonSchemaCredential according to the Verifiable Credentials Data Model v2',
  type: 'object',
  properties: {
    type: {
      type: 'array',
      const: ['VerifiableCredential', 'JsonSchemaCredential'],
    },
    credentialSubject: {
      type: 'object',
      properties: {
        type: {
          type: 'string',
          const: 'JsonSchema',
        },
        jsonSchema: {
          $ref: 'https://json-schema.org/draft/2020-12/schema',
        },
      },
      required: ['type', 'jsonSchema'],
    },
    credentialSchema: {
      type: 'object',
      properties: {
        id: {
          type: 'string',
          const: 'https://www.w3.org/ns/credentials/json-schema/v2.json',
        },
        type: {
          type: 'string',
          const: 'JsonSchema',
        },
        digestSRI: {
          type: 'string',
        },
      },
      required: ['id', 'type', 'digestSRI'],
    },
  },
  required: ['type', 'credentialSubject', 'credentialSchema'],
}

const EXAMPLES_V2_URL = 'https://www.w3.org/ns/credentials/examples/v2'
const examplesV2Context = { '@context': { '@vocab': 'https://www.w3.org/ns/credentials/examples#' } }
const ED25519_2020_URL = 'https://w3id.org/security/suites/ed25519-2020/v1'
// vendored copy of the ed25519-2020 context (not bundled by credo's loader)
const ed25519Suite2020Context = {
  '@context': {
    id: '@id',
    type: '@type',
    '@protected': true,
    proof: { '@id': 'https://w3id.org/security#proof', '@type': '@id', '@container': '@graph' },
    Ed25519VerificationKey2020: {
      '@id': 'https://w3id.org/security#Ed25519VerificationKey2020',
      '@context': {
        '@protected': true,
        id: '@id',
        type: '@type',
        controller: { '@id': 'https://w3id.org/security#controller', '@type': '@id' },
        revoked: {
          '@id': 'https://w3id.org/security#revoked',
          '@type': 'http://www.w3.org/2001/XMLSchema#dateTime',
        },
        publicKeyMultibase: {
          '@id': 'https://w3id.org/security#publicKeyMultibase',
          '@type': 'https://w3id.org/security#multibase',
        },
      },
    },
    Ed25519Signature2020: {
      '@id': 'https://w3id.org/security#Ed25519Signature2020',
      '@context': {
        '@protected': true,
        id: '@id',
        type: '@type',
        challenge: 'https://w3id.org/security#challenge',
        created: {
          '@id': 'http://purl.org/dc/terms/created',
          '@type': 'http://www.w3.org/2001/XMLSchema#dateTime',
        },
        domain: 'https://w3id.org/security#domain',
        expires: {
          '@id': 'https://w3id.org/security#expiration',
          '@type': 'http://www.w3.org/2001/XMLSchema#dateTime',
        },
        nonce: 'https://w3id.org/security#nonce',
        proofPurpose: {
          '@id': 'https://w3id.org/security#proofPurpose',
          '@type': '@vocab',
          '@context': {
            '@protected': true,
            id: '@id',
            type: '@type',
            assertionMethod: {
              '@id': 'https://w3id.org/security#assertionMethod',
              '@type': '@id',
              '@container': '@set',
            },
            authentication: {
              '@id': 'https://w3id.org/security#authenticationMethod',
              '@type': '@id',
              '@container': '@set',
            },
            capabilityInvocation: {
              '@id': 'https://w3id.org/security#capabilityInvocationMethod',
              '@type': '@id',
              '@container': '@set',
            },
            capabilityDelegation: {
              '@id': 'https://w3id.org/security#capabilityDelegationMethod',
              '@type': '@id',
              '@container': '@set',
            },
            keyAgreement: {
              '@id': 'https://w3id.org/security#keyAgreementMethod',
              '@type': '@id',
              '@container': '@set',
            },
          },
        },
        proofValue: {
          '@id': 'https://w3id.org/security#proofValue',
          '@type': 'https://w3id.org/security#multibase',
        },
        verificationMethod: { '@id': 'https://w3id.org/security#verificationMethod', '@type': '@id' },
      },
    },
  },
}

// serves the examples vocab and 2020 suite context from memory so signing never leaves the
// process; DID urls are framed here too because credo's internal frame call bypasses wrappers
export const v4TestDocumentLoader = (agentContext: AgentContext) => {
  const base = new W3cCredentialsModuleConfig().documentLoader(agentContext)
  const loader = async (
    url: string,
  ): Promise<{ contextUrl: null; documentUrl: string; document: unknown }> => {
    if (url === EXAMPLES_V2_URL) {
      return { contextUrl: null, documentUrl: url, document: examplesV2Context }
    }
    if (url === ED25519_2020_URL) {
      return { contextUrl: null, documentUrl: url, document: ed25519Suite2020Context }
    }
    if (url.startsWith('did:')) {
      const didResolver = agentContext.dependencyManager.resolve(DidResolverService)
      const result = await didResolver.resolve(agentContext, url)
      if (!result.didDocument) throw new Error(`Unable to resolve DID: ${url}`)
      const framed = await vcLibraries.jsonld.frame(
        result.didDocument.toJSON(),
        { '@context': result.didDocument.context, '@embed': '@never', id: url },
        { documentLoader: loader },
      )
      return { contextUrl: null, documentUrl: url, document: framed }
    }
    return base(url)
  }
  return loader
}

const HOST = 'v4-agent.example'
export const v4Did = `did:web:${HOST}`
const VPR_SCHEME = 'vpr:verana:vna-devnet-1'
const ISSUANCE_DATE = '2024-01-01T00:00:00Z'
const VPR_ORIGIN = 'https://idx.devnet.verana.network'
const W3C_META_URL = 'https://www.w3.org/ns/credentials/json-schema/v2.json'

// fetchMocker serves text() as JSON.stringify(data), so SRI digests cover exactly those bytes
const sriOf = (data: unknown): string =>
  `sha256-${createHash('sha256').update(JSON.stringify(data)).digest('base64')}`

type MockResponses = Record<string, { ok: boolean; status?: number; data: unknown }>

export interface V4Fixtures {
  did: string
  didDocument: Record<string, unknown>
  credoDidDocument: DidDocument
  mockResponses: MockResponses
}

export async function buildV4Fixtures(agent: Agent): Promise<V4Fixtures> {
  const { keyId, publicJwk } = await agent.kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })
  const publicKeyMultibase = Kms.PublicJwk.fromPublicJwk(publicJwk).fingerprint
  const vmId = `${v4Did}#key-1`

  const didDocument: Record<string, unknown> = {
    '@context': [
      'https://w3id.org/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
      'https://identity.foundation/linked-vp/contexts/v1',
    ],
    id: v4Did,
    verificationMethod: [
      { id: vmId, type: 'Ed25519VerificationKey2020', controller: v4Did, publicKeyMultibase },
    ],
    authentication: [vmId],
    assertionMethod: [vmId],
    service: [
      {
        id: `${v4Did}#vpr-schemas-service-vtc-vp`,
        type: 'LinkedVerifiablePresentation',
        serviceEndpoint: `https://${HOST}/vt/vpr-schemas-service-vtc-vp.json`,
      },
      {
        id: `${v4Did}#vpr-schemas-org-vtc-vp`,
        type: 'LinkedVerifiablePresentation',
        serviceEndpoint: `https://${HOST}/vt/vpr-schemas-org-vtc-vp.json`,
      },
    ],
  }

  const credoDidDocument = JsonTransformer.fromJSON(didDocument, DidDocument)
  await agent.dids.import({
    did: v4Did,
    didDocument: credoDidDocument,
    keys: [{ didDocumentRelativeKeyId: '#key-1', kmsKeyId: keyId }],
    overwrite: true,
  })
  // credo resolves the verification method through DidResolverService while signing
  vi.spyOn(DidResolverService.prototype, 'resolve').mockResolvedValue({
    didResolutionMetadata: {},
    didDocumentMetadata: {},
    didDocument: credoDidDocument,
  })

  const proofPurpose = new vcLibraries.jsonldSignatures.purposes.AssertionProofPurpose()
  const signCredential = async (json: Record<string, unknown>): Promise<W3cJsonLdVerifiableCredential> =>
    agent.w3cCredentials.signCredential({
      format: ClaimFormat.LdpVc,
      credential: JsonTransformer.fromJSON(json, W3cCredential),
      proofType: 'Ed25519Signature2020',
      verificationMethod: vmId,
      proofPurpose,
    })
  const signPresentation = async (json: Record<string, unknown>): Promise<W3cJsonLdVerifiablePresentation> =>
    agent.w3cCredentials.signPresentation({
      format: ClaimFormat.LdpVp,
      presentation: JsonTransformer.fromJSON(json, W3cPresentation),
      proofType: 'Ed25519Signature2020',
      verificationMethod: vmId,
      proofPurpose,
    })

  const mockResponses: MockResponses = {
    [W3C_META_URL]: { ok: true, data: jsonSchemaCredentialMetaSchema },
    [EXAMPLES_V2_URL]: { ok: true, data: examplesV2Context },
  }

  const subjects: Record<'service' | 'org', Record<string, unknown>> = {
    service: {
      id: v4Did,
      name: 'V4 Demo Service',
      type: 'ECommerce',
      description: 'Dynamic v4 fixture service',
      logoUri: `https://${HOST}/logo.png`,
      logoDigestSri: 'sha384-AAAA',
      minimumAgeRequired: 18,
      termsAndConditionsUri: `https://${HOST}/terms`,
      termsAndConditionsDigestSri: 'sha384-BBBB',
      privacyPolicyUri: `https://${HOST}/privacy`,
      privacyPolicyDigestSri: 'sha384-CCCC',
    },
    org: {
      id: v4Did,
      name: 'V4 Demo Org',
      logoUri: `https://${HOST}/logo.png`,
      logoDigestSri: 'sha384-DDDD',
      registryId: 'REG-1',
      address: '1 Demo Street, Demo City',
      countryCode: 'US',
    },
  }

  for (const kind of ['service', 'org'] as const) {
    const schemaId = kind === 'service' ? 132 : 133
    const schemaBody = essentialSchemas[kind === 'service' ? 'ecs-service' : 'ecs-org']
    const refUrl = `${VPR_SCHEME}:cs:${schemaId}`
    const jscUrl = `https://${HOST}/vt/schemas-${kind}-jsc.json`
    const vpUrl = `https://${HOST}/vt/vpr-schemas-${kind}-vtc-vp.json`

    const jsc = await signCredential({
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        ED25519_2020_URL,
        { '@vocab': 'https://www.w3.org/ns/credentials/examples#' },
      ],
      id: jscUrl,
      type: ['VerifiableCredential', 'JsonSchemaCredential'],
      issuer: v4Did,
      issuanceDate: '2024-01-01T00:00:00Z',
      expirationDate: '2099-01-01T00:00:00Z',
      credentialSubject: {
        id: refUrl,
        type: 'JsonSchema',
        jsonSchema: { $ref: refUrl },
        digestSRI: sriOf(schemaBody),
      },
      credentialSchema: {
        id: W3C_META_URL,
        type: 'JsonSchema',
        digestSRI: sriOf(jsonSchemaCredentialMetaSchema),
      },
    })

    const vtc = await signCredential({
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        ED25519_2020_URL,
        { '@vocab': 'https://www.w3.org/ns/credentials/examples#' },
      ],
      id: `https://${HOST}/vt/${kind}-vtc.json`,
      type: ['VerifiableCredential', 'VerifiableTrustCredential'],
      issuer: v4Did,
      issuanceDate: '2024-01-01T00:00:00Z',
      expirationDate: '2099-01-01T00:00:00Z',
      credentialSubject: subjects[kind],
      credentialSchema: { id: jscUrl, type: 'JsonSchemaCredential' },
    })

    const vp = await signPresentation({
      '@context': ['https://www.w3.org/2018/credentials/v1', ED25519_2020_URL],
      id: vpUrl,
      type: ['VerifiablePresentation'],
      holder: v4Did,
      verifiableCredential: [JsonTransformer.toJSON(vtc)],
    })

    mockResponses[vpUrl] = { ok: true, data: JsonTransformer.toJSON(vp) }
    mockResponses[jscUrl] = { ok: true, data: JsonTransformer.toJSON(jsc) }
    mockResponses[`${VPR_ORIGIN}/v4/credential-schema/js/${schemaId}`] = { ok: true, data: schemaBody }
    mockResponses[`${VPR_ORIGIN}/v4/credential-schema/get/${schemaId}`] = {
      ok: true,
      data: {
        schema: {
          id: schemaId,
          ecosystem_id: 1,
          digest_algorithm: 'sha384',
          json_schema: JSON.stringify(schemaBody),
        },
      },
    }
    // [IDX-VT-EVAL-1] anchoring at the issuance instant keeps the participant mock below valid
    const digestJCS = computeCredentialDigestJCS(JsonTransformer.toJSON(vtc) as never, 'sha384')
    mockResponses[`${VPR_ORIGIN}/v4/di/get/${encodeURIComponent(digestJCS)}`] = {
      ok: true,
      data: { digest: { digest: digestJCS, created: ISSUANCE_DATE } },
    }
    mockResponses[
      `${VPR_ORIGIN}/v4/participant/list?did=${encodeURIComponent(v4Did)}&role=HOLDER&schema_id=${schemaId}&when=${encodeURIComponent(ISSUANCE_DATE)}`
    ] = { ok: true, data: { participants: [] } }
    mockResponses[
      `${VPR_ORIGIN}/v4/participant/list?did=${encodeURIComponent(v4Did)}&role=ISSUER&schema_id=${schemaId}&when=${encodeURIComponent(ISSUANCE_DATE)}`
    ] = { ok: true, data: mockParticipant }
  }

  return { did: v4Did, didDocument, credoDidDocument, mockResponses }
}
