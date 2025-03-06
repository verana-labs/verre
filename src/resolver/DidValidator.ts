import { identifySchema } from '../utils';
import * as didWeb from 'web-did-resolver';
import { ECS, ResolveResult } from '../types';
import { Resolver, ServiceEndpoint } from 'did-resolver';
import { JsonLdObject, VerifiableCredential } from '@transmute/verifiable-credentials';

export class DidValidator {
  private resolverInstance: Resolver;

  constructor() {
    const webDidResolver = didWeb.getResolver();
    this.resolverInstance = new Resolver(webDidResolver);
  }

  public async resolve(did: string): Promise<ResolveResult> {
    if (!did) {
      return { result: false, message: 'Invalid DID URL' };
    }

    try {
      const resolutionResult = await this.resolverInstance.resolve(did);
      if (!resolutionResult || !resolutionResult.didDocument) {
        return {
          result: false,
          message: `DID resolution failed for ${did}`,
        };
      }
      const didDocument = resolutionResult.didDocument;

      if (!didDocument?.service?.length) {
        return {
          result: false,
          didDocument,
          message: 'No services found in DID Document',
        };
      }

      for (const { type, serviceEndpoint } of didDocument.service) {
        if (type !== 'LinkedVerifiablePresentation' && type !== 'VerifiablePublicRegistry') {
          return { result: false, message: `Unsupported service type: ${type}` };
        }
        if (type === 'LinkedVerifiablePresentation') {
          const vpResult = await this.fetchLinkedVP(serviceEndpoint);
          if (!vpResult.result) return vpResult;
        } else if (type === 'VerifiablePublicRegistry') {
          return this.fetchTrustRegistry(serviceEndpoint);
        }
      }

      return { result: true, didDocument };
    } catch (error) {
      return {
        result: false,
        message: `Error resolving DID Document: ${error}`,
      };
    }
  }

  private async fetchLinkedVP(serviceEndpoint: ServiceEndpoint): Promise<ResolveResult> {
    const endpoints = Array.isArray(serviceEndpoint) ? serviceEndpoint : [serviceEndpoint];
    const validEndpoints = endpoints.filter(ep => typeof ep === 'string') as string[];

    if (!validEndpoints.length) {
      return { result: false, message: 'No valid service endpoints found.' };
    }

    try {
      await Promise.all(validEndpoints.map(async (endpoint) => {
        const response = await fetch(endpoint);
        if (!response.ok) throw new Error(`Error fetching VP from ${endpoint}: ${response.statusText}`);

        const responseJson = await response.json() as { verifiableCredential: VerifiableCredential };
        const { issuer, id, credentialSchema } = responseJson.verifiableCredential;
        console.info(`Linked VP from ${endpoint}:`, responseJson.verifiableCredential);

        const schemaMatch = identifySchema(credentialSchema);
        if (!schemaMatch) {
          return { result: false, message: 'VP does not match any known schema.' };
        }

        return {
          result: issuer === id && [ECS.ORG, ECS.PERSON].some(v => schemaMatch?.includes(v)) || schemaMatch === ECS.SERVICE,
        };
      }));
    } catch (error) {
      return { result: false, message: `Failed to fetch Linked VP: ${error}` };
    }

    return { result: true };
  }

  private fetchTrustRegistry(serviceEndpoint: ServiceEndpoint): ResolveResult {
    return { result: false, message: 'Method not implemented.' };
  }
}
