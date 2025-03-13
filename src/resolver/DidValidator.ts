import * as didWeb from 'web-did-resolver';
import { CredentialSchema, ECS, Permission, PermissionType, ResolveResult } from '../types';
import { Resolver, Service } from 'did-resolver';
import { JsonLdObject, VerifiableCredential, VerifiablePresentation } from '@transmute/verifiable-credentials';
import Ajv, { ValidateFunction } from 'ajv/dist/2020';
import addFormats from "ajv-formats";
import { checkSchemaMatch, identifySchema } from '../utils';

export class DidValidator {
  private resolverInstance: Resolver;
  private trustRegistryUrl: String;

  constructor() {
    const webDidResolver = didWeb.getResolver();
    this.resolverInstance = new Resolver(webDidResolver);
    this.trustRegistryUrl = 'http://testTrust.org'; // TODO: check this url
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
      const { didDocument } = await this.retrieveDidDocument(did);
      if (!didDocument?.service) {
        return { result: false, message: 'Failed to retrieve DID Document with service.' };
      }

      for (const service of didDocument.service) {
        if (service.type === 'LinkedVerifiablePresentation') {
          const credential = await this.extractCredentialFromVP(service);
          if (credential) verifiableCredentials.push(credential);
        } else if (service.type === 'VerifiablePublicRegistry') {
          await this.queryTrustRegistry(service);
        }
      }
      const isValid = verifiableCredentials.some(vc => {
        const schema = identifySchema(vc.credentialSubject);
        return vc.issuer === did && schema !== null && [ECS.ORG, ECS.PERSON].includes(schema);
      });

      if (!isValid) {
        const permResponse = await fetch(`${this.trustRegistryUrl}/prem/v1/get`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ did }),
        });
        
        if (!permResponse.ok) return { result: false, didDocument };
        const permission: Permission = await permResponse.json() as Permission;
        
        if (permission.type !== PermissionType.ISSUER) return { result: false, didDocument };

        const schemaResponse = await fetch(`${this.trustRegistryUrl}/cs/v1/get`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: permission.schema_id }),
        });
        
        if (!schemaResponse.ok) return { result: false, didDocument };
        const credentialSchema: CredentialSchema = await schemaResponse.json() as CredentialSchema;

        const schemaType = checkSchemaMatch(credentialSchema.json_schema as ECS);
        return { result: schemaType !== null && [ECS.ORG, ECS.PERSON].includes(schemaType), didDocument };
      }

      return { result: isValid, didDocument };
    } catch (error) {
      return { result: false, message: `Error resolving DID Document: ${error}` };
    }
  }

  /**
   * Fetches and validates a DID Document.
   * @param did - The DID to fetch.
   * @returns A promise resolving to the resolution result.
   */
  private async retrieveDidDocument(did: string): Promise<ResolveResult> {
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
      throw new Error("Missing 'VerifiablePublicRegistry' entry for existing '#vpr-schemas'.");
    }
    if (hasTrustRegistry && !hasLinkedPresentation) {
      throw new Error("Missing 'LinkedVerifiablePresentation' entry for existing '#vpr-schemas'.");
    }
    if (hasEssentialSchemas && !hasEssentialTrustRegistry) {
      throw new Error("Missing 'VerifiablePublicRegistry' entry for existing '#vpr-essential-schemas'.");
    }
    if (hasEssentialTrustRegistry && !hasEssentialSchemas) {
      throw new Error("Missing 'LinkedVerifiablePresentation' entry for existing '#vpr-essential-schemas-trust-registry'.");
    }

    return { result: true, didDocument };
  }

  /**
   * Resolves a Linked Verifiable Presentation (VP) from a service endpoint.
   * @param service - The service containing the VP.
   * @returns A promise resolving to the verifiable credential.
   */
  private async extractCredentialFromVP(service: Service): Promise<VerifiableCredential> {
    const endpoints = Array.isArray(service.serviceEndpoint) ? service.serviceEndpoint : [service.serviceEndpoint];
    const validEndpoints = endpoints.filter(ep => typeof ep === 'string') as string[];
    if (!validEndpoints.length) throw new Error("No valid endpoints found");

    for (const endpoint of validEndpoints) {
      try {
        const response = await fetch(endpoint);
        if (response.ok) {
          const vp = await response.json() as VerifiablePresentation;
          const credential = this.getVerifiedCredential(vp); // TODO: handle many verifiableCredential??
          return await this.checkCredentialSchema(credential);
        }
        throw new Error(`Error fetching VP from ${endpoint}: ${response.statusText}`);
      } catch (error) {
        throw new Error(`Failed to fetch VP from ${endpoint}: ${error}`);
      }
    }
    throw new Error('No valid endpoints found')
  }

  /**
   * Fetches and validates exists data from a Trust Registry service.
   * @param service - The Trust Registry service to query.
   * @throws Error if the service endpoint is invalid or unreachable.
   */
  private async queryTrustRegistry(service: Service) {
    if (!service.serviceEndpoint || !Array.isArray(service.serviceEndpoint) || service.serviceEndpoint.length === 0) {
        throw new Error("The service does not have a valid endpoint.");
    }

    try {
        const response = await fetch(service.serviceEndpoint[0], { method: "GET" });

        if (!response.ok) {
          throw new Error(`The service responded with code ${response.status}.`);
        }
    } catch (error) {
        throw new Error(`Error querying the Trust Registry: ${error.message}`);
    }
  }
  
  /**
   * Extracts a valid verifiable credential from a Verifiable Presentation.
   * @param vp - The Verifiable Presentation to parse.
   * @returns A valid Verifiable Credential.
   * @throws Error if no valid credential is found.
   */
  private getVerifiedCredential(vp: VerifiablePresentation): VerifiableCredential {
    if (!vp.verifiableCredential || vp.verifiableCredential.length === 0) {
      throw new Error('No verifiable credential found in the response');
    }
    const validCredential = vp.verifiableCredential.find(vc =>
      vc.type.includes('VerifiableCredential')
    ) as VerifiableCredential | undefined;          
    if (!validCredential) {
      throw new Error('No valid verifiable credential found in the response');
    }

    return validCredential;
  }

  /**
   * Validates a Verifiable Credential's schema against expected trust criteria.
   * @param credential - The Verifiable Credential to validate.
   * @returns A promise resolving to the validated Verifiable Credential.
   * @throws Error if validation fails.
   */
  private async checkCredentialSchema(credential: VerifiableCredential): Promise<VerifiableCredential> {
    if (!credential.credentialSchema || !credential.credentialSubject) {
      throw new Error("Missing 'credentialSchema' or 'credentialSubject' in Verifiable Trust Credential.");
    }

    const credentialSchema = Array.isArray(credential.credentialSchema) ? credential.credentialSchema[0] : credential.credentialSchema;
    let credentialSubject = Array.isArray(credential.credentialSubject) ? credential.credentialSubject[0] : credential.credentialSubject;
    const { id, type } = credentialSchema as Record<string, any>;
    if (!id?.startsWith('http') || type !== 'JsonSchemaCredential') {
      throw new Error(`Invalid credential schema: id must be a valid URL and type must be 'JsonSchemaCredential'.`);
    }

    try {
      // Check credential 
      const schemaResponse = await fetch(id);
      if (!schemaResponse.ok) throw new Error(`Failed to fetch schema from ${id}`);
      const schema = (await schemaResponse.json()) as CredentialSchema;

      // Check Schema
      const refUrl = credentialSubject && typeof credentialSubject === "object" &&
            "jsonSchema" in credentialSubject && (credentialSubject as any).jsonSchema?.$ref;
      if (refUrl) {
        const refResponse = await fetch(refUrl);
        if (!refResponse.ok) throw new Error(`Failed to fetch referenced schema from ${refUrl}`);
        credentialSubject = (await refResponse.json()) as JsonLdObject;
      }

      // Validations
      const schemaObject = JSON.parse(schema.json_schema);
      const ajv = new Ajv();
      addFormats(ajv);
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
