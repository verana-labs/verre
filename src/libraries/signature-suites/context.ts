export const ED25519_SUITE_CONTEXT_URL_2018 = 'https://w3id.org/security/suites/ed25519-2018/v1'
export const ED25519_SUITE_CONTEXT_URL_2020 = 'https://w3id.org/security/suites/ed25519-2020/v1'

export const context = {
  '@context': {
    id: '@id',
    type: '@type',
    '@protected': true,

    proof: {
      '@id': 'https://w3id.org/security#proof',
      '@type': '@id',
      '@container': '@graph',
    },
    Ed25519VerificationKey2018: {
      '@id': 'https://w3id.org/security#Ed25519VerificationKey2018',
      '@context': {
        '@protected': true,
        id: '@id',
        type: '@type',
        controller: {
          '@id': 'https://w3id.org/security#controller',
          '@type': '@id',
        },
        revoked: {
          '@id': 'https://w3id.org/security#revoked',
          '@type': 'http://www.w3.org/2001/XMLSchema#dateTime',
        },
        publicKeyBase58: {
          '@id': 'https://w3id.org/security#publicKeyBase58',
        },
      },
    },
    Ed25519Signature2018: {
      '@id': 'https://w3id.org/security#Ed25519Signature2018',
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
        jws: {
          '@id': 'https://w3id.org/security#jws',
        },
        verificationMethod: {
          '@id': 'https://w3id.org/security#verificationMethod',
          '@type': '@id',
        },
      },
    },
  },
}

export const context2020 = {
  '@context': {
    id: '@id',
    type: '@type',
    '@protected': true,
    proof: {
      '@id': 'https://w3id.org/security#proof',
      '@type': '@id',
      '@container': '@graph',
    },
    Ed25519VerificationKey2020: {
      '@id': 'https://w3id.org/security#Ed25519VerificationKey2020',
      '@context': {
        '@protected': true,
        id: '@id',
        type: '@type',
        controller: {
          '@id': 'https://w3id.org/security#controller',
          '@type': '@id',
        },
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
        verificationMethod: {
          '@id': 'https://w3id.org/security#verificationMethod',
          '@type': '@id',
        },
      },
    },
  },
}

const ed25519Signature2018Context = new Map()
ed25519Signature2018Context.set(ED25519_SUITE_CONTEXT_URL_2018, context)
const ed25519Signature2020Context = new Map()
ed25519Signature2020Context.set(ED25519_SUITE_CONTEXT_URL_2020, context2020)

export { ed25519Signature2018Context, ed25519Signature2020Context }
