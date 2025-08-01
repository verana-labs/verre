// __mocks__/didMocks.ts

import { ECS, loadSchema } from '../../src'

export const didExtIssuer = 'did:web:issuer.trusted.example.com'
export const didSelfIssued = 'did:web:service.self-issued.example.com'

export const mockDidDocumentSelfIssued = {
  didDocument: {
    id: didSelfIssued,
    service: [
      {
        id: `${didSelfIssued}#vpr-schemas`,
        type: 'LinkedVerifiablePresentation',
        serviceEndpoint: ['https://example.com/vp-ser-self-issued'],
      },
      {
        id: `${didSelfIssued}#vpr-schemas`,
        type: 'LinkedVerifiablePresentation',
        serviceEndpoint: ['https://example.com/vp-org'],
      },
      {
        id: `${didSelfIssued}#vpr-schemas-trust-registry`,
        type: 'VerifiablePublicRegistry',
        serviceEndpoint: ['https://example.com/trust-registry'],
      },
    ],
  },
}

export const mockDidDocumentSelfIssuedExtIssuer = {
  didDocument: {
    id: didExtIssuer,
    service: [
      {
        id: `${didExtIssuer}#vpr-schemas`,
        type: 'LinkedVerifiablePresentation',
        serviceEndpoint: ['https://example.com/vp-ser-ext-issued'],
      },
      {
        id: `${didExtIssuer}#vpr-schemas-trust-registry`,
        type: 'VerifiablePublicRegistry',
        serviceEndpoint: ['https://example.com/trust-registry'],
      },
    ],
  },
}

export const mockResolverSelfIssued = {
  didResolutionMetadata: {},
  didDocumentMetadata: {},
  ...mockDidDocumentSelfIssued,
}

export const mockResolverExtIssuer = {
  didResolutionMetadata: {},
  didDocumentMetadata: {},
  ...mockDidDocumentSelfIssuedExtIssuer,
}

export const createVerifiableCredential = (
  issuer: string,
  credentialSchema: Record<string, any>,
  credentialSubject: Record<string, any>,
) => ({
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    {
      schema: 'https://schema.org/',
    },
  ],
  id: 'https://example.tr/credentials/OrganizationJsonSchemaCredential',
  issuer,
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
})

export const createVerifiablePresentation = (
  holder: string,
  issuer: string,
  credentialSchema: Record<string, any>,
  credentialSubject: Record<string, any>,
) => {
  const verifiableCredential = createVerifiableCredential(issuer, credentialSchema, credentialSubject)

  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    holder,
    type: ['VerifiablePresentation'],
    verifiableCredential: [verifiableCredential],
    id: `https://example.com/verifiable-presentation-${holder}.jsonld`,
    proof: {
      type: 'Ed25519Signature2018',
      created: '2024-02-08T17:38:46Z',
      verificationMethod: `${issuer}#key-1`,
      proofPurpose: 'assertionMethod',
      jws: 'eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..signature',
    },
  }
}

export const mockServiceVcSelfIssued = createVerifiablePresentation(
  'did:example:123',
  didSelfIssued,
  {
    id: 'https://ecs-trust-registry/service-credential-schema-credential.json',
    type: 'JsonSchemaCredential',
  },
  {
    id: 'did:example:self-issued',
    name: 'Example LLC',
    type: 'ServiceCredential',
    description: 'Example service credential',
    logo: 'iVBORw0KGgoAAAANSUhEUgAAA...',
    minimumAgeRequired: 18,
    termsAndConditions: 'https://example.com/terms',
    privacyPolicy: 'https://example.com/privacy',
  },
)

export const mockServiceExtIssuerVc = createVerifiablePresentation(
  'did:example:123',
  didExtIssuer,
  {
    id: 'https://ecs-trust-registry/service-ext-issuer-credential-schema-credential.json',
    type: 'JsonSchemaCredential',
  },
  {
    id: 'did:example:ext-issuer',
    name: 'Example LLC',
    type: 'ServiceCredential',
    description: 'Example service credential',
    logo: 'iVBORw0KGgoAAAANSUhEUgAAA...',
    minimumAgeRequired: 18,
    termsAndConditions: 'https://example.com/terms',
    privacyPolicy: 'https://example.com/privacy',
  },
)

export const mockServiceSchemaSelfIssued = createVerifiableCredential(
  didSelfIssued,
  {
    id: 'https://www.w3.org/ns/credentials/json-schema/v2.json',
    type: 'JsonSchema',
    digestSRI: 'sha256-qm/TCo3y3vnDW3lvcF42wTannkJbyU+uUxWHyl23NKM=',
  },
  {
    id: 'https://vpr-hostname/vpr/v1/cs/js/12345678',
    type: 'JsonSchema',
    jsonSchema: {
      $ref: 'https://vpr-hostname/vpr/v1/cs/js/12345678',
    },
    digestSRI: 'sha256-+HD2SszO0zCJyOCj2VFY65weOqTc/dhTdvzCZgnn6ro=',
  },
)

export const mockServiceSchemaExtIssuer = createVerifiableCredential(
  didSelfIssued,
  {
    id: 'https://www.w3.org/ns/credentials/json-schema/v2.json',
    type: 'JsonSchema',
    digestSRI: 'sha256-qm/TCo3y3vnDW3lvcF42wTannkJbyU+uUxWHyl23NKM=',
  },
  {
    id: 'https://vpr-hostname/vpr/v1/cs/js/12345678',
    type: 'JsonSchema',
    jsonSchema: {
      $ref: 'https://vpr-hostname/vpr/v1/cs/js/12345678',
    },
    digestSRI: 'sha256-+HD2SszO0zCJyOCj2VFY65weOqTc/dhTdvzCZgnn6ro=',
  },
)

export const mockOrgVc = createVerifiablePresentation(
  didSelfIssued,
  didSelfIssued,
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

export const mockOrgSchema = createVerifiableCredential(
  didSelfIssued,
  {
    id: 'https://www.w3.org/ns/credentials/json-schema/v2.json',
    type: 'JsonSchema',
    digestSRI: 'sha256-qm/TCo3y3vnDW3lvcF42wTannkJbyU+uUxWHyl23NKM=',
  },
  {
    id: 'https://vpr-hostname/vpr/v1/cs/js/12345671',
    type: 'JsonSchema',
    jsonSchema: {
      $ref: 'https://vpr-hostname/vpr/v1/cs/js/12345671',
    },
    digestSRI: 'sha256-Z4tIlaf5mtgZiDhYwaz7GJ2aT58vwPjfrYZ0IPfgfaM=',
  },
)

export const mockOrgVcWithoutIssuer = createVerifiablePresentation(
  'did:example:123',
  didSelfIssued,
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

export const mockOrgSchemaWithoutIssuer = createVerifiableCredential(
  didSelfIssued,
  {
    id: 'https://www.w3.org/ns/credentials/json-schema/v2.json',
    type: 'JsonSchema',
    digestSRI: 'sha256-qm/TCo3y3vnDW3lvcF42wTannkJbyU+uUxWHyl23NKM=',
  },
  {
    id: 'https://vpr-hostname/vpr/v1/cs/js/12345673',
    type: 'JsonSchema',
    jsonSchema: {
      $ref: 'https://vpr-hostname/vpr/v1/cs/js/12345673',
    },
    digestSRI: 'sha256-Z4tIlaf5mtgZiDhYwaz7GJ2aT58vwPjfrYZ0IPfgfaM=',
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
  schema: JSON.stringify(loadSchema(ECS.ORG)),
}

export const mockCredentialSchemaSer = {
  schema: JSON.stringify(loadSchema(ECS.SERVICE)),
}

// Mock integration didDocument

export const mockDidDocumentChatbot = JSON.parse(
  '{"@context":["https://w3id.org/did/v1","https://w3id.org/security/suites/ed25519-2018/v1","https://w3id.org/security/suites/x25519-2019/v1"],"id":"did:web:dm.chatbot.demos.dev.2060.io","verificationMethod":[{"id":"did:web:dm.chatbot.demos.dev.2060.io#z6Mkq8fQM7RXugXFtGDEA77mDHTDFVe8RSaxfs2SVxcDX7AY","type":"Ed25519VerificationKey2018","controller":"did:web:dm.chatbot.demos.dev.2060.io","publicKeyBase58":"BgQMksB6a92nmmNXUY9vNBuDRvNH1ZLbyr7WfgeCbtPA"},{"id":"did:web:dm.chatbot.demos.dev.2060.io#key-agreement-1","type":"X25519KeyAgreementKey2019","controller":"did:web:dm.chatbot.demos.dev.2060.io","publicKeyBase58":"GLP1WpxfiKGr813mB3chxa6N2peLm6cfehbC5oQvwJTb"}],"service":[{"id":"did:web:dm.chatbot.demos.dev.2060.io#vpr-ecs-trust-registry-1234","serviceEndpoint":"https://dm.chatbot.demos.dev.2060.io/self-tr","type":"VerifiablePublicRegistry"},{"id":"did:web:dm.chatbot.demos.dev.2060.io#vpr-ecs-service-c-vp","serviceEndpoint":"https://dm.chatbot.demos.dev.2060.io/self-tr/ecs-service-c-vp.json","type":"LinkedVerifiablePresentation"},{"id":"did:web:dm.chatbot.demos.dev.2060.io#vpr-ecs-org-c-vp","serviceEndpoint":"https://dm.chatbot.demos.dev.2060.io/self-tr/ecs-org-c-vp.json","type":"LinkedVerifiablePresentation"},{"id":"did:web:dm.chatbot.demos.dev.2060.io#did-communication","serviceEndpoint":"wss://dm.chatbot.demos.dev.2060.io:443","type":"did-communication","priority":0,"recipientKeys":["did:web:dm.chatbot.demos.dev.2060.io#key-agreement-1"],"routingKeys":[],"accept":["didcomm/aip2;env=rfc19"]},{"id":"did:web:dm.chatbot.demos.dev.2060.io#anoncreds","serviceEndpoint":"https://dm.chatbot.demos.dev.2060.io/anoncreds/v1","type":"AnonCredsRegistry"}],"authentication":["did:web:dm.chatbot.demos.dev.2060.io#z6Mkq8fQM7RXugXFtGDEA77mDHTDFVe8RSaxfs2SVxcDX7AY"],"assertionMethod":["did:web:dm.chatbot.demos.dev.2060.io#z6Mkq8fQM7RXugXFtGDEA77mDHTDFVe8RSaxfs2SVxcDX7AY"],"keyAgreement":["did:web:dm.chatbot.demos.dev.2060.io#key-agreement-1"]}',
)

export const integrationDidDoc = JSON.parse(
  '{"@context":["https://w3id.org/did/v1","https://w3id.org/security/suites/ed25519-2018/v1","https://w3id.org/security/suites/x25519-2019/v1"],"id":"did:web:bcccdd780017.ngrok-free.app","verificationMethod":[{"id":"did:web:bcccdd780017.ngrok-free.app#z6Mki3RxG2xc2zBeipUV8rkbbTKXJ4XCGLKPNn93atRdMzpV","type":"Ed25519VerificationKey2018","controller":"did:web:bcccdd780017.ngrok-free.app","publicKeyBase58":"4bAufniAhShBcKdnTHnkkMmXUVFLrT52gmE7kcTcSn37"},{"id":"did:web:bcccdd780017.ngrok-free.app#key-agreement-1","type":"X25519KeyAgreementKey2019","controller":"did:web:bcccdd780017.ngrok-free.app","publicKeyBase58":"DnVWEnqGMQidQfsxa5wxBEv6YDKkduGnpxtRPMTAJPk3"}],"service":[{"id":"did:web:bcccdd780017.ngrok-free.app#vpr-ecs-trust-registry-1234","serviceEndpoint":"https://api.testnet.verana.network/verana","type":"VerifiablePublicRegistry"},{"id":"did:web:bcccdd780017.ngrok-free.app#vpr-ecs-service-c-vp","serviceEndpoint":"https://bcccdd780017.ngrok-free.app/self-tr/ecs-service-c-vp.json","type":"LinkedVerifiablePresentation"},{"id":"did:web:bcccdd780017.ngrok-free.app#vpr-ecs-org-c-vp","serviceEndpoint":"https://bcccdd780017.ngrok-free.app/self-tr/ecs-org-c-vp.json","type":"LinkedVerifiablePresentation"},{"id":"did:web:bcccdd780017.ngrok-free.app#did-communication","serviceEndpoint":"wss://bcccdd780017.ngrok-free.app","type":"did-communication","priority":0,"recipientKeys":["did:web:bcccdd780017.ngrok-free.app#key-agreement-1"],"routingKeys":[],"accept":["didcomm/aip2;env=rfc19"]},{"id":"did:web:bcccdd780017.ngrok-free.app#anoncreds","serviceEndpoint":"https://bcccdd780017.ngrok-free.app/anoncreds/v1","type":"AnonCredsRegistry"}],"authentication":["did:web:bcccdd780017.ngrok-free.app#z6Mki3RxG2xc2zBeipUV8rkbbTKXJ4XCGLKPNn93atRdMzpV"],"assertionMethod":["did:web:bcccdd780017.ngrok-free.app#z6Mki3RxG2xc2zBeipUV8rkbbTKXJ4XCGLKPNn93atRdMzpV"],"keyAgreement":["did:web:bcccdd780017.ngrok-free.app#key-agreement-1"]}',
)
export const linkedVpService = JSON.parse(
  '{"id":"did:web:bcccdd780017.ngrok-free.app","@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiablePresentation"],"verifiableCredential":[{"@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],"id":"did:web:bcccdd780017.ngrok-free.app","type":["VerifiableCredential","VerifiableTrustCredential"],"issuer":"did:web:bcccdd780017.ngrok-free.app","issuanceDate":"2025-07-25T16:07:14.946Z","expirationDate":"2026-07-25T16:07:14.957Z","credentialSubject":{"name":"chatbot","type":"WEB_PORTAL","description":"Somedescription","logo":"data:image/png;base64,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","minimumAgeRequired":18,"termsAndConditions":"https://example.com/terms","privacyPolicy":"https://example.com/privacy","id":"did:web:bcccdd780017.ngrok-free.app"},"credentialSchema":{"id":"https://bcccdd780017.ngrok-free.app/self-tr/schemas-example-service.json","type":"JsonSchemaCredential"},"proof":{"verificationMethod":"did:web:bcccdd780017.ngrok-free.app#z6Mki3RxG2xc2zBeipUV8rkbbTKXJ4XCGLKPNn93atRdMzpV","type":"Ed25519Signature2018","created":"2025-07-25T16:07:14Z","proofPurpose":"assertionMethod","jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..mIrlqRTwv9d2nzYGMrUcVsJAEoDqk0CtrazlhlVEKM0EvvIMCco5TpKGvX-OkuU7k5_PAZ39vnVBVtGc7bIKCg"}}],"holder":"did:web:bcccdd780017.ngrok-free.app","proof":{"verificationMethod":"did:web:bcccdd780017.ngrok-free.app#z6Mki3RxG2xc2zBeipUV8rkbbTKXJ4XCGLKPNn93atRdMzpV","type":"Ed25519Signature2018","created":"2025-07-25T16:07:15Z","proofPurpose":"authentication","challenge":"challenge","domain":"example.com","jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..THVRMda1xPqCWw_WIevvmAVL5Ih_y9AGDZ5H-U13aEOuL65BshwGR1OVoN8PYs_dAebMnLlRMvYWpkdIgVK4BQ"}}',
)
export const linkedVpOrg = JSON.parse(
  '{"id":"did:web:bcccdd780017.ngrok-free.app","@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiablePresentation"],"verifiableCredential":[{"@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],"id":"did:web:bcccdd780017.ngrok-free.app","type":["VerifiableCredential","VerifiableTrustCredential"],"issuer":"did:web:bcccdd780017.ngrok-free.app","issuanceDate":"2025-07-25T16:07:46.099Z","expirationDate":"2026-07-25T16:07:46.099Z","credentialSubject":{"name":"chatbot","logo":"data:image/png;base64,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","registryId":"ID-123","registryUrl":"https://example.com/registry","address":"Someaddress","type":"PUBLIC","countryCode":"CO","id":"did:web:bcccdd780017.ngrok-free.app"},"credentialSchema":{"id":"https://bcccdd780017.ngrok-free.app/self-tr/schemas-example-org.json","type":"JsonSchemaCredential"},"proof":{"verificationMethod":"did:web:bcccdd780017.ngrok-free.app#z6Mki3RxG2xc2zBeipUV8rkbbTKXJ4XCGLKPNn93atRdMzpV","type":"Ed25519Signature2018","created":"2025-07-25T16:07:46Z","proofPurpose":"assertionMethod","jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..5_0IeQ2JilXvMf6_177ZGFRGWf0QTK7hWWDqgm_pDlJNMt_vD2UQVB3FxEDD37tNupdWhupgG_PTVLH4AECtDA"}}],"holder":"did:web:bcccdd780017.ngrok-free.app","proof":{"verificationMethod":"did:web:bcccdd780017.ngrok-free.app#z6Mki3RxG2xc2zBeipUV8rkbbTKXJ4XCGLKPNn93atRdMzpV","type":"Ed25519Signature2018","created":"2025-07-25T16:07:46Z","proofPurpose":"authentication","challenge":"challenge","domain":"example.com","jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..rSsTfdtvnLl-FQF1KrCFCoOT5LCtU2ejfnIGu-gh-DHxYdSXDrekj_msfuAykE0BCxRzhJz9E6JnBQb8MwVnAQ"}}',
)
export const jsonSchemaCredentialService = JSON.parse(
  '{"@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],"id":"did:web:bcccdd780017.ngrok-free.app","type":["VerifiableCredential","JsonSchemaCredential"],"issuer":"did:web:bcccdd780017.ngrok-free.app","issuanceDate":"2025-07-25T16:08:15.411Z","expirationDate":"2026-07-25T16:08:15.411Z","credentialSubject":{"type":"JsonSchema","jsonSchema":{"$ref":"https://api.testnet.verana.network/verana/cs/v1/js/3"},"digestSRI":"sha256-6YbmSu2VdpfyxKL8cQz8mzLP1ql7G8BRQjjqLjnw6EM=","id":"https://api.testnet.verana.network/verana/cs/v1/js/3"},"credentialSchema":{"id":"https://www.w3.org/ns/credentials/json-schema/v2.json","type":"JsonSchema","digestSRI":"sha256-qm/TCo3y3vnDW3lvcF42wTannkJbyU+uUxWHyl23NKM="},"proof":{"verificationMethod":"did:web:bcccdd780017.ngrok-free.app#z6Mki3RxG2xc2zBeipUV8rkbbTKXJ4XCGLKPNn93atRdMzpV","type":"Ed25519Signature2018","created":"2025-07-25T16:08:16Z","proofPurpose":"assertionMethod","jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..pgFkhFzCmrvN38OjDcZqqieeYr1GOB7rQisE4arkxpoCl9DTwDSZiFHIl1cb14jdBVkQsWFxFxycfnhZrH_CAw"}}',
)
export const jsonSchemaCredentialOrg = JSON.parse(
  '{"@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],"id":"did:web:bcccdd780017.ngrok-free.app","type":["VerifiableCredential","JsonSchemaCredential"],"issuer":"did:web:bcccdd780017.ngrok-free.app","issuanceDate":"2025-07-25T16:08:36.216Z","expirationDate":"2026-07-25T16:08:36.216Z","credentialSubject":{"type":"JsonSchema","jsonSchema":{"$ref":"https://api.testnet.verana.network/verana/cs/v1/js/6"},"digestSRI":"sha256-1HcKQdsxahY3172gggcDISCtYSUNyNw3efo+CNV8gNs=","id":"https://api.testnet.verana.network/verana/cs/v1/js/1"},"credentialSchema":{"id":"https://www.w3.org/ns/credentials/json-schema/v2.json","type":"JsonSchema","digestSRI":"sha256-qm/TCo3y3vnDW3lvcF42wTannkJbyU+uUxWHyl23NKM="},"proof":{"verificationMethod":"did:web:bcccdd780017.ngrok-free.app#z6Mki3RxG2xc2zBeipUV8rkbbTKXJ4XCGLKPNn93atRdMzpV","type":"Ed25519Signature2018","created":"2025-07-25T16:08:37Z","proofPurpose":"assertionMethod","jws":"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..3uP8_BVfNi9BdRpRvIQLXO438Y9ZNsBSKygVF97NyZgkfcl5TCHXSvNa4CirTMYK4AfvXqHq-zHnGQ74-2zXDA"}}',
)
