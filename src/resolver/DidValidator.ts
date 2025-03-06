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
      const didDocument = (await this.fetchDidDocument(did)).didDocument;
      if (!didDocument) return { result: false, message: 'Failed to retrieve DID Document.' };

      for (const { type, serviceEndpoint } of didDocument.service) {
        if (type === 'LinkedVerifiablePresentation') {
          const vpResult = await this.fetchLinkedVP(serviceEndpoint);
          if (!vpResult.result) return { ...vpResult, didDocument };
        } else if (type === 'VerifiablePublicRegistry') {
          return this.fetchTrustRegistry(serviceEndpoint);
        }
      }

      return { result: true, didDocument };
    } catch (error) {
      return { result: false, message: `Error resolving DID Document: ${error}` };
    }
  }

  private async fetchDidDocument(did: string): Promise<ResolveResult> {
    const errors: string[] = [];

    // Resolve the DID document
    const resolutionResult = await this.resolverInstance.resolve(did);
    const didDocument = resolutionResult?.didDocument;
    if (!didDocument) {
      return { result: false, message: `DID resolution failed for ${did}` };
    }

    // Validate service entries
    if (!didDocument.service?.length) {
      return { result: false, didDocument, message: "No services found in the DID Document." };
    }
    const hasLinkedPresentation = didDocument.service.some(service =>
      service.type === "LinkedVerifiablePresentation" && service.id.includes("#vpr-schemas")
    );
    const hasTrustRegistry = didDocument.service.some(service =>
      service.type === "VerifiablePublicRegistry" && service.id.includes("#vpr-schemas-trust-registry")
    );
    if (!hasLinkedPresentation) {
      errors.push("Missing 'LinkedVerifiablePresentation' entry with '#vpr-schemas'.");
    }
    if (!hasTrustRegistry) {
      errors.push("Missing 'VerifiablePublicRegistry' entry with '#vpr-schemas-trust-registry'.");
    }

    return errors.length > 0
      ? { result: false, didDocument, message: errors.join(" ") }
      : { result: true, didDocument };
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
        console.info(`Linked VP from ${endpoint}:`, responseJson.verifiableCredential);

        const schemaMatch = identifySchema(responseJson.verifiableCredential.credentialSchema);
        if (!schemaMatch) {
          return { result: false, message: 'VP does not match any known schema.' };
        }

        return {
          result: responseJson.verifiableCredential.issuer === responseJson.verifiableCredential.id &&
            [ECS.ORG, ECS.PERSON].some(v => schemaMatch?.includes(v)) || schemaMatch === ECS.SERVICE,
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
