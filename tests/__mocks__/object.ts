// __mocks__/didMocks.ts

import { ECS, loadSchema } from '../../src'

export const mockDidDocument = {
  didDocument: {
    id: 'did:web:example.com',
    service: [
      {
        id: 'did:web:example.com#vpr-schemas',
        type: 'LinkedVerifiablePresentation',
        serviceEndpoint: ['https://example.com/vp-ser'],
      },
      {
        id: 'did:web:example.com#vpr-schemas',
        type: 'LinkedVerifiablePresentation',
        serviceEndpoint: ['https://example.com/vp-org'],
      },
      {
        id: 'did:web:example.com#vpr-schemas-trust-registry',
        type: 'VerifiablePublicRegistry',
        serviceEndpoint: ['https://example.com/trust-registry'],
      },
    ],
  },
}

export const didDocumentChatbot = {
  context: [
    'https://w3id.org/did/v1',
    'https://w3id.org/security/suites/ed25519-2018/v1',
    'https://w3id.org/security/suites/x25519-2019/v1',
  ],
  id: 'did:web:chatbot-demo.dev.2060.io',
  verificationMethod: [
    {
      id: 'did:web:chatbot-demo.dev.2060.io#verkey',
      type: 'Ed25519VerificationKey2018',
      controller: 'did:web:chatbot-demo.dev.2060.io',
      publicKeyBase58: '4MNFY8hDy5o6eZj6DojRA2N41peJTZT61dwR4zRGoVKi',
    },
    {
      id: 'did:web:chatbot-demo.dev.2060.io#key-agreement-1',
      type: 'X25519KeyAgreementKey2019',
      controller: 'did:web:chatbot-demo.dev.2060.io',
      publicKeyBase58: 'CtoYyZd3GWEBH2n8j5LcasFxRVofpYkcp6qDjukiRSxR',
    },
  ],
  service: [
    {
      id: 'did:web:chatbot-demo.dev.2060.io#did-communication',
      serviceEndpoint: 'wss://chatbot-demo.dev.2060.io:443',
      type: 'did-communication',
      priority: 0,
      recipientKeys: ['did:web:chatbot-demo.dev.2060.io#key-agreement-1'],
      routingKeys: [],
      accept: ['didcomm/aip2;env=rfc19'],
    },
    {
      id: 'did:web:chatbot-demo.dev.2060.io#anoncreds',
      serviceEndpoint: 'https://chatbot-demo.dev.2060.io/anoncreds/v1',
      type: 'AnonCredsRegistry',
    },
  ],
  authentication: ['did:web:chatbot-demo.dev.2060.io#verkey'],
  assertionMethod: ['did:web:chatbot-demo.dev.2060.io#verkey'],
  keyAgreement: ['did:web:chatbot-demo.dev.2060.io#key-agreement-1'],
}

export const mockResolverInstance = {
  didResolutionMetadata: {},
  didDocumentMetadata: {},
  ...mockDidDocument,
}

export const createMockVerifiableCredential = (
  holder: string,
  issuer: string,
  credentialSchema: Record<string, any>,
  credentialSubject: Record<string, any>,
) => ({
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  holder: holder,
  type: ['VerifiablePresentation'],
  verifiableCredential: [
    {
      context: [
        'https://www.w3.org/2018/credentials/v1',
        {
          schema: 'https://schema.org/',
        },
      ],
      id: 'https://example.tr/credentials/OrganizationJsonSchemaCredential',
      issuer: issuer,
      issuanceDate: '2024-02-08T18:38:46+01:00',
      expirationDate: new Date(new Date().setFullYear(new Date().getFullYear() + 5)).toISOString(),
      type: ['VerifiableCredential', 'JsonSchemaCredential'],
      credentialSubject: {
        ...credentialSubject,
      },
      credentialSchema: {
        ...credentialSchema,
      },
      proof: {
        type: 'Ed25519Signature2018',
        created: '2024-02-08T17:38:46Z',
        verificationMethod: `${issuer}#key-1`,
        proofPurpose: 'assertionMethod',
        jws: 'eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..signature',
      },
    },
  ],
  id: `https://example.com/verifiable-presentation-${holder}.jsonld`,
  proof: {
    type: 'Ed25519Signature2018',
    created: '2024-02-08T17:38:46Z',
    verificationMethod: `${issuer}#key-1`,
    proofPurpose: 'assertionMethod',
    jws: 'eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..signature',
  },
})

export const mockServiceVerifiableCredential = createMockVerifiableCredential(
  'did:example:123',
  'did:example:123',
  {
    id: 'https://ecs-trust-registry/service-credential-schema-credential.json',
    type: 'JsonSchemaCredential',
  },
  {
    id: 'did:example:123',
    name: 'Example LLC',
    type: 'ServiceCredential',
    description: 'Example service credential',
    logo: 'iVBORw0KGgoAAAANSUhEUgAAA...',
    minimumAgeRequired: 18,
    termsAndConditions: 'https://example.com/terms',
    privacyPolicy: 'https://example.com/privacy',
  },
)

export const mockServiceSchema = createMockVerifiableCredential(
  'did:example:123',
  'did:example:123',
  {
    id: 'https://www.w3.org/ns/credentials/json-schema/v2.json',
    type: 'JsonSchema',
    digestSRI: 'sha384-flPoqoltLFFs9AdL8mJzZUFYRJ4SZ04JrtlGt5MIgGr5dsFHlBwwC20PyS0iIdVe',
  },
  {
    id: 'https://vpr-hostname/vpr/v1/cs/js/12345678',
    type: 'JsonSchema',
    jsonSchema: {
      $ref: 'https://vpr-hostname/vpr/v1/cs/js/12345678',
    },
    digestSRI: 'sha384-57G/HBKgp3Pd2TsDegvouVagiWpbE8dW8as4zw/tkRg288SWqOZNi4ZIySRvdfnt',
  },
)

export const mockOrgVerifiableCredential = createMockVerifiableCredential(
  'did:web:example.com',
  'did:web:example.com',
  {
    id: 'https://ecs-trust-registry/org-credential-schema-credential.json',
    type: 'JsonSchemaCredential',
  },
  {
    id: 'did:example:456',
    name: 'Example Corp',
    logo: 'iVBORw0KGgoAAAANSUhEUgAAAAUA...',
    registryId: 'EX-123456',
    registryUrl: 'https://registry.example.com/org/EX-123456',
    address: '123 Example Street, Example City, EX 10001',
    type: 'PUBLIC',
    countryCode: 'US',
  },
)

export const mockOrgSchema = createMockVerifiableCredential(
  'did:example:123',
  'did:example:123',
  {
    id: 'https://www.w3.org/ns/credentials/json-schema/v2.json',
    type: 'JsonSchema',
    digestSRI: 'sha384-flPoqoltLFFs9AdL8mJzZUFYRJ4SZ04JrtlGt5MIgGr5dsFHlBwwC20PyS0iIdVe',
  },
  {
    id: 'https://vpr-hostname/vpr/v1/cs/js/12345671',
    type: 'JsonSchema',
    jsonSchema: {
      $ref: 'https://vpr-hostname/vpr/v1/cs/js/12345671',
    },
    digestSRI: 'sha384-v2VdV9qYgGCe1qyerE7jY8LTfvgD88UgqNgDpPjDD0yTWt5P81PUjhyZZnpRjh3P',
  },
)

export const mockOrgVerifiableCredentialWithoutIssuer = createMockVerifiableCredential(
  'did:example:123',
  'did:example:123',
  {
    id: 'https://ecs-trust-registry/org-credential-schema-credential.json',
    type: 'JsonSchemaCredential',
  },
  {
    id: 'did:example:456',
    name: 'Example Corp',
    logo: 'iVBORw0KGgoAAAANSUhEUgAAAAUA...',
    registryId: 'EX-123456',
    registryUrl: 'https://registry.example.com/org/EX-123456',
    address: '123 Example Street, Example City, EX 10001',
    type: 'PUBLIC',
    countryCode: 'US',
  },
)

export const mockOrgSchemaWithoutIssuer = createMockVerifiableCredential(
  'did:example:123',
  'did:example:123',
  {
    id: 'https://www.w3.org/ns/credentials/json-schema/v2.json',
    type: 'JsonSchema',
    digestSRI: 'sha384-flPoqoltLFFs9AdL8mJzZUFYRJ4SZ04JrtlGt5MIgGr5dsFHlBwwC20PyS0iIdVe',
  },
  {
    id: 'https://vpr-hostname/vpr/v1/cs/js/12345673',
    type: 'JsonSchema',
    jsonSchema: {
      $ref: 'https://vpr-hostname/vpr/v1/cs/js/12345673',
    },
    digestSRI: 'sha384-v2VdV9qYgGCe1qyerE7jY8LTfvgD88UgqNgDpPjDD0yTWt5P81PUjhyZZnpRjh3P',
  },
)

export const mockPermission = {
  id: 1,
  schema_id: 100,
  type: 'ISSUER',
  grantee: 'user123',
  created: 1710000000,
  created_by: 'admin',
  extended: 1710003600,
  extended_by: 'admin',
  modified: 1710007200,
  validation_fees: 10,
  issuance_fees: 5,
  verification_fees: 2,
  deposit: 50,
  revoked_by: '',
  terminated_by: '',
  vp_state: 'PENDING',
  vp_last_state_change: 1710010800,
  vp_current_fees: 3,
  vp_current_deposit: 20,
}

export const mockCredentialSchemaOrg = {
  id: 100,
  tr_id: 1001,
  created: '2024-03-12T12:00:00Z',
  modified: '2024-03-12T12:30:00Z',
  archived: '',
  deposit: 5000,
  json_schema: JSON.stringify(loadSchema(ECS.ORG)),
  issuer_grantor_validation_validity_period: 365,
  verifier_grantor_validation_validity_period: 180,
  issuer_validation_validity_period: 730,
  verifier_validation_validity_period: 90,
  holder_validation_validity_period: 60,
  issuer_perm_management_mode: 'STRICT',
  verifier_perm_management_mode: 'FLEXIBLE',
}

export const mockCredentialSchemaSer = {
  id: 101,
  tr_id: 1002,
  created: '2024-03-12T12:00:00Z',
  modified: '2024-03-12T12:30:00Z',
  archived: '',
  deposit: 5000,
  json_schema: JSON.stringify(loadSchema(ECS.SERVICE)),
  issuer_grantor_validation_validity_period: 365,
  verifier_grantor_validation_validity_period: 180,
  issuer_validation_validity_period: 730,
  verifier_validation_validity_period: 90,
  holder_validation_validity_period: 60,
  issuer_perm_management_mode: 'STRICT',
  verifier_perm_management_mode: 'FLEXIBLE',
}
