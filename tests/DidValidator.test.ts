import { getResolver } from 'web-did-resolver';
import { Resolver } from 'did-resolver';
import { DidValidator, ECS, loadSchema } from '../src';
import { mockCredentialSchema, mockDidDocument, mockOrgVerifiableCredential, mockPermission, mockResolverInstance, mockServiceVerifiableCredential } from './__mocks__/object';
import { fetchMocker } from './__mocks__/fetch';

describe('DidValidator', () => {
  let didValidator: DidValidator;
  let resolverInstance: Resolver;

  beforeEach(() => {
    resolverInstance = new Resolver(getResolver());
    didValidator = new DidValidator();

    fetchMocker.enable();
  });
  
  afterEach(() => {
    fetchMocker.reset();
    fetchMocker.disable();
    jest.clearAllMocks();
  });

  describe('resolver method', () => {
    it('should fail for a valid web DID without LinkedVerifiablePresentation', async () => {
      // Real case with 'chatbot-demo.dev.2060.io'
      const domain = 'chatbot-demo.dev.2060.io';
      const did = `did:web:${domain}`;

      // Setup spy methods
      const resolveSpy = jest.spyOn(Resolver.prototype, 'resolve');
      const fetchLinkedVPSpy = jest.spyOn(didValidator as any, 'resolveLinkedVP');
      const fetchTrustRegistrySpy = jest.spyOn(didValidator as any, 'fetchTrustRegistry');


      // Execute method under test
      const result = await didValidator.resolve(did);

      // Testing
      expect(resolveSpy).toHaveBeenCalledTimes(1);
      expect(resolveSpy).toHaveBeenCalledWith(did);
      expect(fetchTrustRegistrySpy).not.toHaveBeenCalled();
      expect(fetchLinkedVPSpy).not.toHaveBeenCalled();
      expect(result).toEqual(expect.objectContaining({ result: false }));
    });

    it('should work correctly under expected conditions', async () => {
      // Init values
      const did = `did:web:example.com`;
      
      // mocked data
      const resolverInstanceSpy = jest.spyOn(didValidator['resolverInstance'], 'resolve').mockResolvedValue({ ...mockResolverInstance });
      fetchMocker.setMockResponses({
        "https://example.com/vp-ser": { ok: true, status: 200, data: mockServiceVerifiableCredential },
        "https://ecs-trust-registry/service-credential-schema-credential.json": { ok: true, status: 200, data: { json_schema: JSON.stringify(loadSchema(ECS.SERVICE)) }},
        "https://example.com/vp-org": { ok: true, status: 200, data: mockOrgVerifiableCredential },
        "https://ecs-trust-registry/organization-credential-schema-credential.json": { ok: true, status: 200, data: { json_schema: JSON.stringify(loadSchema(ECS.ORG)) }},
        "https://example.com/trust-registry": { ok: true, status: 200, data: {} },
        "http://testTrust.org/prem/v1/get": { ok: true, status: 200, data: mockPermission },
        "http://testTrust.org/cs/v1/get": { ok: true, status: 200, data: mockCredentialSchema },
      });

      // Execute method under test
      const result = await didValidator.resolve(did);
      expect(resolverInstanceSpy).toHaveBeenCalledWith('did:web:example.com');
      expect(result).toEqual(expect.objectContaining({ result: true, ...mockDidDocument }));
    });
  });
});