import * as didWeb from 'web-did-resolver';
import { CredentialSchema, ECS, ResolveResult } from '../types';
import { Resolver, Service } from 'did-resolver';
import { JsonLdObject, VerifiableCredential } from '@transmute/verifiable-credentials';
import Ajv, { ValidateFunction } from 'ajv';
import { identifySchema } from '../utils';

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
    const verifiableCredentials: VerifiableCredential[] = [];
    if (!did) return { result: false, message: 'Invalid DID URL' };

    try {
      const { didDocument } = await this.fetchDidDocument(did);
      if (!didDocument?.service) {
        return { result: false, message: 'Failed to retrieve DID Document with service.' };
      }

      for (const service of didDocument.service) {
        if (service.type === 'LinkedVerifiablePresentation') {
          const credentials = await this.resolveLinkedVP(service);
          if (!Array.isArray(credentials)) {
            throw new Error('resolveLinkedVP must return an array of VerifiableCredential');
          }
          verifiableCredentials.push(...credentials);
        } else if (service.type === 'VerifiablePublicRegistry') {
          return this.fetchTrustRegistry(service);
        }
      }
      const isValid = verifiableCredentials.some(vc => {
        const schema = identifySchema(vc.credentialSchema);
        return vc.issuer === did && schema !== null && [ECS.ORG, ECS.PERSON].includes(schema);
      });

      return { result: isValid, didDocument };
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
  private async resolveLinkedVP(service: Service): Promise<VerifiableCredential> {
    const endpoints = Array.isArray(service.serviceEndpoint) ? service.serviceEndpoint : [service.serviceEndpoint];
    const validEndpoints = endpoints.filter(ep => typeof ep === 'string') as string[];
    if (!validEndpoints.length) throw new Error("No valid endpoints found");

    for (const endpoint of validEndpoints) {
      try {
        const response = await fetch(endpoint);
        if (response.ok) {
          const { verifiableCredential } = await response.json() as { verifiableCredential: VerifiableCredential };
          return await this.validateCredential(verifiableCredential);
        }
        throw new Error(`Error fetching VP from ${endpoint}: ${response.statusText}`);
      } catch (error) {
        throw new Error(`Failed to fetch VP from ${endpoint}: ${error}`);
      }
    }
    throw new Error('No valid endpoints found')
  }

  /**
   * Placeholder for trust registry fetching logic.
   */
  private async fetchTrustRegistry(service: Service): Promise<ResolveResult> {
    if (!service.serviceEndpoint || !Array.isArray(service.serviceEndpoint) || service.serviceEndpoint.length === 0) {
        return { result: false, message: "The service does not have a valid endpoint." };
    }

    try {
        const response = await fetch(service.serviceEndpoint[0], { method: "GET" });

        if (!response.ok) {
          return { result: false, message: `The service responded with code ${response.status}.` };
        }
        return { result: true }
    } catch (error) {
        return { result: false, message: `Error querying the Trust Registry: ${error.message}` };
    }
  }

  /**
   * Validates a Verifiable Credential's schema against expected trust criteria.
   */
  private async validateCredential(credential: VerifiableCredential): Promise<VerifiableCredential> {
    if (!credential.credentialSchema || !credential.credentialSubject) {
      throw new Error("Missing 'credentialSchema' or 'credentialSubject' in Verifiable Trust Credential.");
    }

    const credentialSchema = Array.isArray(credential.credentialSchema) ? credential.credentialSchema[0] : credential.credentialSchema;
    let credentialSubject = Array.isArray(credential.credentialSubject) ? credential.credentialSubject[0] : credential.credentialSubject;
    const { id, type } = credentialSchema as Record<string, any>;
    if (!id || typeof id !== 'string' || !id.startsWith('http')) {
      throw new Error("Invalid 'id' in credentialSchema. Must be a valid URL.");
    }
    if (type !== 'JsonSchemaCredential') {
      throw new Error("Invalid 'type' in credentialSchema. Must be 'JsonSchemaCredential'.");
    }

    try {
      // Check credential 
      const schemaResponse = await fetch(id);
      if (!schemaResponse.ok) throw new Error(`Failed to fetch schema from ${id}`);
      const data = (await schemaResponse.json()) as { schema: CredentialSchema };

      // Check Schema
      const refUrl = credentialSubject && typeof credentialSubject === "object" &&
            "jsonSchema" in credentialSubject && (credentialSubject as any).jsonSchema?.$ref;
      if (refUrl) {
        const refResponse = await fetch(refUrl);
        if (!refResponse.ok) throw new Error(`Failed to fetch referenced schema from ${refUrl}`);
        credentialSubject = (await refResponse.json()) as { credentialSubject: JsonLdObject };
      }

      // Validations
      const schemaObject = JSON.parse(data.schema.json_schema);
      const ajv = new Ajv();
      const validate: ValidateFunction = ajv.compile(schemaObject);
      const isValid = validate(credentialSubject);
  
      if (!isValid) {
        throw new Error(`Credential does not conform to schema: ${JSON.stringify(validate.errors)}`);
      }  
      return credential;
    } catch (error) {
      throw new Error(`Failed to validate credential: ${error.message}`);
    }
  }
}
