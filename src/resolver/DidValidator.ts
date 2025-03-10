import { identifySchema } from '../utils';
import * as didWeb from 'web-did-resolver';
import { ECS, ResolveResult } from '../types';
import { Resolver, Service } from 'did-resolver';
import { VerifiableCredential } from '@transmute/verifiable-credentials';

export class DidValidator {
  private resolverInstance: Resolver;

  constructor() {
    const webDidResolver = didWeb.getResolver();
    this.resolverInstance = new Resolver(webDidResolver);
  }

  /**
   * Resolves a DID and validates its document and associated services.
   * @param did - The DID to resolve.
   * @returns A promise resolving to the resolution result.
   */
  public async resolve(did: string): Promise<ResolveResult> {
    if (!did) return { result: false, message: 'Invalid DID URL' };

    try {
      const { didDocument } = await this.fetchDidDocument(did);
      if (!didDocument?.service) {
        return { result: false, message: 'Failed to retrieve DID Document with service.' };
      }

      for (const service of didDocument.service) {
        if (service.type === 'LinkedVerifiablePresentation') {
          await this.resolveLinkedVP(service);
        } else if (service.type === 'VerifiablePublicRegistry') {
          return this.fetchTrustRegistry(service);
        }
      }

      return { result: false, didDocument };
    } catch (error) {
      return { result: false, message: `Error resolving DID Document: ${error}` };
    }
  }

  /**
   * Fetches and validates a DID Document.
   */
  private async fetchDidDocument(did: string): Promise<ResolveResult> {
    const errors: string[] = [];
    const resolutionResult = await this.resolverInstance.resolve(did);
    const didDocument = resolutionResult?.didDocument;
    if (!didDocument) return { result: false, message: `DID resolution failed for ${did}` };

    const serviceEntries = didDocument.service || [];
    if (!serviceEntries.length) return { result: false, didDocument, message: 'No services found in the DID Document.' };

    // Validate presence of "vpr-schemas"
    const hasLinkedPresentation = serviceEntries.some(s => s.type === 'LinkedVerifiablePresentation' && s.id.includes('#vpr-schemas'));
    const hasTrustRegistry = serviceEntries.some(s => s.type === 'VerifiablePublicRegistry' && s.id.includes('#vpr-schemas-trust-registry'));

    // Validate presence of "vpr-essential-schemas"
    const hasEssentialSchemas = serviceEntries.some(s => s.type === 'LinkedVerifiablePresentation' && s.id.includes('#vpr-essential-schemas'));
    const hasEssentialTrustRegistry = serviceEntries.some(s => s.type === 'VerifiablePublicRegistry' && s.id.includes('#vpr-essential-schemas-trust-registry'));

    // Validate schema consistency
    if (hasLinkedPresentation && !hasTrustRegistry) {
      errors.push("Missing 'VerifiablePublicRegistry' entry for existing '#vpr-schemas'.");
    }
    if (hasTrustRegistry && !hasLinkedPresentation) {
      errors.push("Missing 'LinkedVerifiablePresentation' entry for existing '#vpr-schemas-trust-registry'.");
    }
    if (hasEssentialSchemas && !hasEssentialTrustRegistry) {
      errors.push("Missing 'VerifiablePublicRegistry' entry for existing '#vpr-essential-schemas'.");
    }
    if (hasEssentialTrustRegistry && !hasEssentialSchemas) {
      errors.push("Missing 'LinkedVerifiablePresentation' entry for existing '#vpr-essential-schemas-trust-registry'.");
    }

    return errors.length ? { result: false, didDocument, message: errors.join(' ') } : { result: true, didDocument };
  }

  /**
   * Resolves a Linked Verifiable Presentation (VP) from a service endpoint.
   */
  private async resolveLinkedVP(service: Service): Promise<VerifiableCredential | null> {
    const endpoints = Array.isArray(service.serviceEndpoint) ? service.serviceEndpoint : [service.serviceEndpoint];
    const validEndpoints = endpoints.filter(ep => typeof ep === 'string') as string[];
    if (!validEndpoints.length) return null;

    for (const endpoint of validEndpoints) {
      try {
        const response = await fetch(endpoint);
        if (!response.ok) throw new Error(`Error fetching VP from ${endpoint}: ${response.statusText}`);
        const { verifiableCredential } = await response.json();
        return await this.validateServiceTrustCredential(verifiableCredential);
      } catch (error) {
        console.error(`Failed to fetch VP from ${endpoint}: ${error}`);
      }
    }
    return null;
  }

  /**
   * Fetches and returns a schema from a given URL.
   */
  private async fetchSchema(url: string): Promise<any> {
    try {
      const response = await fetch(url);
      if (!response.ok) throw new Error(`Failed to fetch schema from ${url}`);
      return await response.json();
    } catch (error) {
      console.error("Error fetching schema:", error);
      return null;
    }
  }

  /**
   * Validates a Verifiable Credential's schema against expected trust criteria.
   */
  private async validateServiceTrustCredential(credential: VerifiableCredential): Promise<ResolveResult> {
    if (!credential.credentialSchema) {
      return { result: false, message: "Missing 'credentialSchema' in Verifiable Trust Credential." };
    }

    const credentialSchema = Array.isArray(credential.credentialSchema) ? credential.credentialSchema[0] : credential.credentialSchema;
    const { id, type } = credentialSchema as Record<string, any>;
    if (!id || typeof id !== 'string' || !id.startsWith('http')) {
      return { result: false, message: "Invalid 'id' in credentialSchema. Must be a valid URL." };
    }
    if (type !== 'JsonSchemaCredential') {
      return { result: false, message: "Invalid 'type' in credentialSchema. Must be 'JsonSchemaCredential'." };
    }
    const schema = await this.fetchSchema(id);
    if (!schema) return { result: false, message: 'Invalid schema format.' };

    const schemaMatch = identifySchema(schema);
    if (!schemaMatch) return { result: false, message: 'VP does not match any known schema.' };

    if (credential.issuer === credential.id && [ECS.ORG, ECS.PERSON].some(v => schemaMatch?.includes(v))) {
      return { result: false, message: 'Schema must be of type "organization" or "person" for essential services.' };
    }
    return { result: true };
  }

  /**
   * Placeholder for trust registry fetching logic.
   */
  private fetchTrustRegistry(service: Service): ResolveResult {
    return { result: false, message: 'Method not implemented.' };
  }
}
