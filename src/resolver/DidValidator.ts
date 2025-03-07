import { identifySchema } from '../utils';
import * as didWeb from 'web-did-resolver';
import { ECS, ResolveResult } from '../types';
import { Resolver, Service, ServiceEndpoint } from 'did-resolver';
import { VerifiableCredential } from '@transmute/verifiable-credentials';

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
      if (!didDocument || !didDocument.service) return { result: false, message: 'Failed to retrieve DID Document with service.' };

      for (const service of didDocument.service) {
        if (service.type === 'LinkedVerifiablePresentation') {
          const vpResult = await this.fetchLinkedVP(service);
          if (!vpResult.result) return { ...vpResult, didDocument };
        } else if (service.type === 'VerifiablePublicRegistry') {
          return this.fetchTrustRegistry(service.serviceEndpoint);
        }
      }

      return { result: false, didDocument };
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

    // Validate presence of "vpr-schemas"
    const hasLinkedPresentation = didDocument.service.some(service =>
      service.type === "LinkedVerifiablePresentation" && service.id.includes("#vpr-schemas")
    );
    const hasTrustRegistry = didDocument.service.some(service =>
      service.type === "VerifiablePublicRegistry" && service.id.includes("#vpr-schemas-trust-registry")
    );

    // Validate presence of "vpr-essential-schemas"
    const hasEssentialSchemas = didDocument.service.some(service =>
      service.type === "LinkedVerifiablePresentation" && service.id.includes("#vpr-essential-schemas")
    );
    const hasEssentialTrustRegistry = didDocument.service.some(service =>
      service.type === "VerifiablePublicRegistry" && service.id.includes("#vpr-essential-schemas-trust-registry")
    );

    // Validate schema presence
    if (!(hasLinkedPresentation || hasEssentialSchemas)) {
      errors.push("Missing 'LinkedVerifiablePresentation' entry with '#vpr-schemas' or '#vpr-essential-schemas'.");
    }
    if (!(hasTrustRegistry || hasEssentialTrustRegistry)) {
      errors.push("Missing 'VerifiablePublicRegistry' entry with '#vpr-schemas-trust-registry' or '#vpr-essential-schemas-trust-registry'.");
    }

    return errors.length > 0
      ? { result: false, didDocument, message: errors.join(" ") }
      : { result: true, didDocument };
  }

  /**
   * Fetches the Linked Verifiable Presentation (VP) from the provided service endpoint(s),
   * validates its credential schema, and ensures it matches the expected trust registry credentials.
   *
   * @param serviceEndpoint - A single service endpoint or an array of endpoints to fetch the VP from.
   * @returns A promise resolving to a `ResolveResult` object indicating whether the VP is valid.
   */
  private async fetchLinkedVP(service: Service): Promise<ResolveResult> {
    const endpoints = Array.isArray(service.serviceEndpoint) ? service.serviceEndpoint : [service.serviceEndpoint];
    const validEndpoints = endpoints.filter(ep => typeof ep === 'string') as string[];
    if (!validEndpoints.length) {
      return { result: false, message: 'No valid service endpoints found.' };
    }

    try {
      const results = await Promise.all(validEndpoints.map(async (endpoint) => {
        const response = await fetch(endpoint);
        if (!response.ok) throw new Error(`Error fetching VP from ${endpoint}: ${response.statusText}`);

        const responseJson = await response.json() as { verifiableCredential: VerifiableCredential };
        console.info(`Linked VP from ${endpoint}:`, responseJson.verifiableCredential);

        const verifiableCredential = responseJson.verifiableCredential;
        if (service.id.includes('#vpr-essential-schemas-service-credential-schema-credential')) return await this.validateServiceTrustCredential(verifiableCredential)

        return { result: false };
      }));

      // Return the first failure result if found, otherwise return success
      const failedResult = results.find(res => res.result === false);
      return failedResult || { result: true };

    } catch (error) {
      return { result: false, message: `Failed to fetch Linked VP: ${error}` };
    }
  }

  /**
   * Fetches the schema from a given URL and returns the JSON response.
   *
   * @param url - The URL of the schema to fetch.
   * @returns A promise resolving to the fetched schema or null if an error occurs.
   */
  private async fetchSchema(url: string): Promise<any> {
    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`Failed to fetch schema from ${url}`);
      }
      return await response.json();
    } catch (error) {
      console.error("Error fetching schema:", error);
      return null;
    }
  }

  private fetchTrustRegistry(serviceEndpoint: ServiceEndpoint): ResolveResult {
    return { result: false, message: 'Method not implemented.' };
  }

  private async validateServiceTrustCredential(credential: VerifiableCredential): Promise<ResolveResult> {
    const errors: string[] = [];

    // Ensure credentialSchema exists
    if (!credential.credentialSchema) {
        return { result: false, message: "Missing 'credentialSchema' property in the Verifiable Trust Credential." };
    }

    // Handle cases where credentialSchema could be an object or an array
    const credentialSchema = Array.isArray(credential.credentialSchema) 
        ? credential.credentialSchema[0] // Take the first one if it's an array
        : credential.credentialSchema;

    // Validate credentialSchema properties
    const { id, type } = credentialSchema as Record<string, any>;
    if (!id || typeof id !== "string" || !id.startsWith("http")) {
        errors.push("Invalid or missing 'id' in credentialSchema. It must be a valid URL.");
    }
    if (type !== "JsonSchemaCredential") {
        errors.push("Invalid 'type' in credentialSchema. It must be 'JsonSchemaCredential'.");
    }
    const schema = await this.fetchSchema(id);
    if (!schema) {
      errors.push('Credential schema is not of type JsonSchemaCredential.');
    }
    console.info("✅ Credential schema is valid for service.");

    // Identify schema type and verify if it matches the expected type (ORG, PERSON, or SERVICE)
    const schemaMatch = identifySchema(schema);
    if (!schemaMatch) {
      errors.push('VP does not match any known schema.');
    }
    if (credential.issuer === credential.id &&
      [ECS.ORG, ECS.PERSON].some(v => schemaMatch?.includes(v)))
      errors.push('The schema must be of type "organization" or "person" if it is part of an essential service.');

    return errors.length > 0
        ? { result: false, message: errors.join(" ") }
        : { result: true };
  }
}
