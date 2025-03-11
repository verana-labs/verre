// __mocks__/didMocks.ts

import { PermissionType } from '../../src';

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
