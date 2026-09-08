// VC Data Model 2.0 fixtures secured with DataIntegrityProof / eddsa-jcs-2022.
//
// Signed with credo-ts main (0.7.1-pr-2704-20260905135824 snapshot: W3cV2CredentialsApi with the
// w3cDataIntegrity module) exactly the way vs-agent publishes a Verifiable Trust Credential: a did:web
// document with an Ed25519VerificationKey2020 method, each ECS credential secured for assertionMethod
// and wrapped in a linked presentation secured for authentication by the same key, both carrying the
// document @context in the proof. Static because the credo release verre builds against (0.7.0)
// cannot produce Data Integrity proofs yet.

export const vcdm2Did = 'did:web:vcdm2.example'
export const vcdm2VerificationMethodId =
  'did:web:vcdm2.example#z6MkiTHgdwSHhMRSgHaUNPRnPgy16wo6JKcfpLuaLHXAQ7Q7'

export const vcdm2DidDocument = {
  '@context': [
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/suites/ed25519-2020/v1',
    'https://identity.foundation/linked-vp/contexts/v1',
  ],
  id: 'did:web:vcdm2.example',
  verificationMethod: [
    {
      id: 'did:web:vcdm2.example#z6MkiTHgdwSHhMRSgHaUNPRnPgy16wo6JKcfpLuaLHXAQ7Q7',
      type: 'Ed25519VerificationKey2020',
      controller: 'did:web:vcdm2.example',
      publicKeyMultibase: 'z6MkiTHgdwSHhMRSgHaUNPRnPgy16wo6JKcfpLuaLHXAQ7Q7',
    },
  ],
  authentication: ['did:web:vcdm2.example#z6MkiTHgdwSHhMRSgHaUNPRnPgy16wo6JKcfpLuaLHXAQ7Q7'],
  assertionMethod: ['did:web:vcdm2.example#z6MkiTHgdwSHhMRSgHaUNPRnPgy16wo6JKcfpLuaLHXAQ7Q7'],
  service: [
    {
      id: 'did:web:vcdm2.example#vpr-schemas-service-vtc-vp',
      type: 'LinkedVerifiablePresentation',
      serviceEndpoint: ['https://vcdm2.example/vt/vpr-schemas-service-vtc-vp.json'],
    },
    {
      id: 'did:web:vcdm2.example#vpr-schemas-org-vtc-vp',
      type: 'LinkedVerifiablePresentation',
      serviceEndpoint: ['https://vcdm2.example/vt/vpr-schemas-org-vtc-vp.json'],
    },
  ],
}

export const vcdm2ServiceVp = {
  id: 'https://vcdm2.example/vt/vpr-schemas-service-vtc-vp.json',
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiablePresentation'],
  verifiableCredential: [
    {
      '@context': ['https://www.w3.org/ns/credentials/v2', 'https://www.w3.org/ns/credentials/examples/v2'],
      id: 'https://vcdm2.example/vt/vtc-service',
      type: ['VerifiableCredential', 'VerifiableTrustCredential'],
      issuer: 'did:web:vcdm2.example',
      credentialSubject: {
        name: 'VCDM 2.0 Demo Service',
        type: 'ECommerce',
        description: 'Service credential secured with a Data Integrity proof',
        logoUri: 'https://vcdm2.example/logo.png',
        logoDigestSri: 'sha384-AAAA',
        minimumAgeRequired: 18,
        termsAndConditionsUri: 'https://vcdm2.example/terms',
        termsAndConditionsDigestSri: 'sha384-BBBB',
        privacyPolicyUri: 'https://vcdm2.example/privacy',
        privacyPolicyDigestSri: 'sha384-CCCC',
        id: 'did:web:vcdm2.example',
      },
      validFrom: '2026-09-01T00:00:00Z',
      validUntil: '2036-09-01T00:00:00Z',
      credentialSchema: {
        id: 'https://ecs-trust-registry/service-credential-schema-credential.json',
        type: 'JsonSchemaCredential',
      },
      proof: {
        type: 'DataIntegrityProof',
        cryptosuite: 'eddsa-jcs-2022',
        verificationMethod: 'did:web:vcdm2.example#z6MkiTHgdwSHhMRSgHaUNPRnPgy16wo6JKcfpLuaLHXAQ7Q7',
        proofPurpose: 'assertionMethod',
        '@context': ['https://www.w3.org/ns/credentials/v2', 'https://www.w3.org/ns/credentials/examples/v2'],
        proofValue:
          'z4z5tY1iDJWfFxtWAXGz92xpirPJRsh6W5jZbvPy2rRUM8LZ8N8mcGC7cHsG3CYVN46kGenTg3Hr53Ec9WSqmycuN',
      },
    },
  ],
  holder: 'did:web:vcdm2.example',
  proof: {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: 'did:web:vcdm2.example#z6MkiTHgdwSHhMRSgHaUNPRnPgy16wo6JKcfpLuaLHXAQ7Q7',
    proofPurpose: 'authentication',
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    proofValue: 'zLXu6hPw5rawb2gu2Z4ukbmanFhkurieH37s4dznz3HgrReBb8XzxpT2jgnBwMinfeDuMjYAZDhAAbBYw8HTZrpW',
  },
}

export const vcdm2OrgVp = {
  id: 'https://vcdm2.example/vt/vpr-schemas-org-vtc-vp.json',
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiablePresentation'],
  verifiableCredential: [
    {
      '@context': ['https://www.w3.org/ns/credentials/v2', 'https://www.w3.org/ns/credentials/examples/v2'],
      id: 'https://vcdm2.example/vt/vtc-org',
      type: ['VerifiableCredential', 'VerifiableTrustCredential'],
      issuer: 'did:web:vcdm2.example',
      credentialSubject: {
        name: 'VCDM 2.0 Demo Org',
        logoUri: 'https://vcdm2.example/logo.png',
        logoDigestSri: 'sha384-DDDD',
        registryId: 'EX-654321',
        address: '1 Demo Street, Demo City',
        countryCode: 'US',
        id: 'did:web:vcdm2.example',
      },
      validFrom: '2026-09-01T00:00:00Z',
      validUntil: '2036-09-01T00:00:00Z',
      credentialSchema: {
        id: 'https://ecs-trust-registry/org-credential-schema-credential.json',
        type: 'JsonSchemaCredential',
      },
      proof: {
        type: 'DataIntegrityProof',
        cryptosuite: 'eddsa-jcs-2022',
        verificationMethod: 'did:web:vcdm2.example#z6MkiTHgdwSHhMRSgHaUNPRnPgy16wo6JKcfpLuaLHXAQ7Q7',
        proofPurpose: 'assertionMethod',
        '@context': ['https://www.w3.org/ns/credentials/v2', 'https://www.w3.org/ns/credentials/examples/v2'],
        proofValue:
          'zoyDGFoXCdMLwaRy2tvYJKTwtUnfuqe8bJZMAFzEmyyVfDBndcrfgHc1qHHzebW2WjxErEeWqHQonfBNT4Z9akeu',
      },
    },
  ],
  holder: 'did:web:vcdm2.example',
  proof: {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: 'did:web:vcdm2.example#z6MkiTHgdwSHhMRSgHaUNPRnPgy16wo6JKcfpLuaLHXAQ7Q7',
    proofPurpose: 'authentication',
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    proofValue: 'z4tume6YusocCPsZy4S5Zsugf8skp8G4B9R8rheAdm1QFe32Qm9q2hxkEaHksoTS97uHEx2JXkzcjuJQ8jYZNa9Wd',
  },
}

export const vcdm2Resolver = {
  didResolutionMetadata: {},
  didDocumentMetadata: {},
  didDocument: vcdm2DidDocument,
}
