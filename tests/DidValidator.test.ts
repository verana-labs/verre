import { getResolver } from 'web-did-resolver';
import { Resolver } from 'did-resolver';
import { DidValidator } from '../src';

describe('DidValidator', () => {
  let didValidator: DidValidator;
  let resolverInstance: Resolver;

  beforeEach(() => {
    resolverInstance = new Resolver(getResolver());
    didValidator = new DidValidator();
    
    // Mock global fetch
    global.fetch = jest.fn();
  });
  
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('resolver method', () => {
    it('should fail for a valid web DID without LinkedVerifiablePresentation', async () => {
      // Real case with 'chatbot-demo.dev.2060.io'
      const domain = 'chatbot-demo.dev.2060.io';
      const did = `did:web:${domain}`;

      // Setup spy methods
      const resolveSpy = jest.spyOn(Resolver.prototype, 'resolve');
      const fetchLinkedVPSpy = jest.spyOn(didValidator as any, 'fetchLinkedVP');
      const fetchTrustRegistrySpy = jest.spyOn(didValidator as any, 'fetchTrustRegistry');


      // Execute method under test
      const result = await didValidator.resolve(did);

      // Testing
      expect(resolveSpy).toHaveBeenCalledTimes(1);
      expect(resolveSpy).toHaveBeenCalledWith(did);
      expect(fetchTrustRegistrySpy).not.toHaveBeenCalled();
      expect(fetchLinkedVPSpy).not.toHaveBeenCalled();
      expect(result.result).toBe(false);    
    });
  });
});