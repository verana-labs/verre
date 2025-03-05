import { identifySchema } from '../utils';
import { getResolver } from 'web-did-resolver'

import { ECS } from '../types';
import { Resolver, ServiceEndpoint } from 'did-resolver';
import { VerifiableCredential } from '@transmute/verifiable-credentials';

const webResolver = getResolver();

const resolver = new Resolver(webResolver);

export class DidValidator {

  async resolver(did: string): Promise<Boolean> {
    if (!did) {
      console.error('Invalid DID URL');
      return false;
    }

    try {
      const didDocument = (await resolver.resolve(did)).didDocument

      if (!didDocument?.service?.length) {
        console.warn('No services found in DID Document');
        return false;
      }

      for (const { type, serviceEndpoint } of didDocument.service) {
        if (type === 'LinkedVerifiablePresentation') {
          await this.fetchLinkedVP(serviceEndpoint);
        } else if (type === 'VerifiablePublicRegistry') {
          await this.fetchTrustRegistry(serviceEndpoint);
        }
      }
    } catch (error) {
      console.error(`Error resolving DID Document: ${error}`);
    }
    return false;
  }

  private async fetchLinkedVP(serviceEndpoint: ServiceEndpoint) {
    const endpoints = Array.isArray(serviceEndpoint) ? serviceEndpoint : [serviceEndpoint];
    const validEndpoints = endpoints.filter(ep => typeof ep === 'string') as string[];

    if (!validEndpoints.length) {
      console.warn('No valid service endpoints found.');
      return false;
    }

    await Promise.all(validEndpoints.map(async (endpoint) => {
      try {
        const response = await fetch(endpoint);
        if (!response.ok) throw new Error(`Error fetching VP from ${endpoint}: ${response.statusText}`);

        const responseJson = await response.json() as { 
          verifiableCredential: VerifiableCredential;
        };
        const { issuer, id, credentialSchema } = responseJson.verifiableCredential
  
        console.info(`Linked VP from ${endpoint}:`, responseJson.verifiableCredential);

        const schemaMatch = identifySchema(credentialSchema);
        schemaMatch 
          ? console.info(`VP matches schema: ${schemaMatch}`) 
          : console.warn('VP does not match any known schema.');

        if (issuer === id && ![ECS.ORG, ECS.PERSON].some(v => schemaMatch?.includes(v))) return false;
        if (schemaMatch === ECS.SERVICE) return true;
      } catch (error) {
        console.error(`Failed to fetch Linked VP from ${endpoint}: ${error}`);
      }
      return false;
    }));
  }

  private fetchTrustRegistry(serviceEndpoint: ServiceEndpoint) {
    throw new Error('Method not implemented.');
  }
}
