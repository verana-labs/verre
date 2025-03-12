// __mocks__/didMocks.ts

export const mockDidDocument = {
  didDocument: {
    id: 'did:web:example.com',
    service: [
      {
        id: 'did:web:example.com#vpr-schemas',
        type: 'LinkedVerifiablePresentation',
        serviceEndpoint: ['https://example.com/vp']
      },
      {
        id: 'did:web:example.com#vpr-schemas-trust-registry',
        type: 'VerifiablePublicRegistry',
        serviceEndpoint: ['https://example.com/trust-registry']
      }
    ]
  }
};

export const mockResolverInstance = {
  didResolutionMetadata: {},
  didDocumentMetadata: {},
  ...mockDidDocument
};

export const mockVerifiableCredential = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1"
    ],
    "holder": "did:example:123",
    "type": [
      "VerifiablePresentation"
    ],
    "verifiableCredential": [
      {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          {
            "schema": "https://schema.org/"
          }
        ],
        "issuer": "did:example:123",
        "issuanceDate": "2024-02-08T18:38:46+01:00",
        "expirationDate": "2029-02-08T18:38:46+01:00",
        "type": [
          "VerifiableCredential",
          "schema:Organization"
        ],
        "credentialSubject": {
          "id": "did:example:123",
          "schema:legalName": "Example LLC",
          "schema:telephone": "+1 23456 789",
          "schema:taxID": "123456789",
          "schema:location": {
            "@type": " PostalAddress",
            "schema:addressCountry": "Example Country",
            "schema:addressRegion": "Example Region",
            "schema:addressLocality": "Example City",
            "schema:postalCode": "12345",
            "schema:streetAddress": "1 Example Street"
          }
        },
        "proof": {
          "type": "Ed25519Signature2018",
          "created": "2024-02-08T17:38:46Z",
          "verificationMethod": "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
          "proofPurpose": "assertionMethod",
          "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..qD1a-op-GWkvzI5LaAXqJhJv-9WCSTgtEUzUvDeuiaUSDWpVUh14x5TUbGNvmx1xZ0fEf5eWZWoJ-2dogDpmBQ"
        }
      }
    ],
    "id": "https://bar.example.com/verifiable-presentation.jsonld",
    "proof": {
      "type": "Ed25519Signature2018",
      "created": "2024-02-08T17:38:46Z",
      "verificationMethod": "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
      "proofPurpose": "assertionMethod",
      "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..6_k6Dbgug-XvksZvDVi9UxUTAmQ0J76pjdrQyNaQL7eVMmP_SUPZCqso6EN3aEKFSsJrjDJoPJa9rBK99mXvDw"
    }
}
