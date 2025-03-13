import { JsonLdObject, VerifiableCredential, VerifiablePresentation } from '@transmute/verifiable-credentials'
import Ajv, { ValidateFunction } from 'ajv/dist/2020'
import addFormats from 'ajv-formats'
import { DIDDocument, Resolver, Service } from 'did-resolver'
import * as didWeb from 'web-did-resolver'

import { CredentialSchema, ECS, Permission, PermissionType, ResolveResult } from '../types'
import { checkSchemaMatch, identifySchema, verifyLinkedVP } from '../utils'

export class DidValidator {
  private resolverInstance: Resolver
  private trustRegistryUrl: string

  constructor() {
    const webDidResolver = didWeb.getResolver()
    this.resolverInstance = new Resolver(webDidResolver)
    this.trustRegistryUrl = 'http://testTrust.org' // TODO: check this url
  }

  /**
   * Resolves a DID and validates its document and associated services.
   * @param did - The DID to resolve.
   * @returns A promise resolving to the resolution result.
   */
  public async resolve(did: string): Promise<ResolveResult> {
    if (!did) return { result: false, message: 'Invalid DID URL' }

    try {
      const { didDocument } = await this.retrieveDidDocument(did)
      if (!didDocument?.service) {
        return { result: false, message: 'Failed to retrieve DID Document with service.' }
      }

      const verifiableCredentials = await this.processDidServices(didDocument.service)
      const isValid = verifiableCredentials.some(vc => {
        const schema = identifySchema(vc.credentialSubject)
        return vc.issuer === did && schema !== null && [ECS.ORG, ECS.PERSON].includes(schema)
      })

      if (!isValid) {
        return this.checkTrustRegistry(did, didDocument)
      }

      return { result: isValid, didDocument }
    } catch (error) {
      return { result: false, message: `Error resolving DID Document: ${error}` }
    }
  }

  /**
   * Processes the DID Document services to extract verifiable credentials.
   *
   * @param {Service[]} services - The list of services from the DID Document.
   * @returns {Promise<VerifiableCredential[]>} A list of extracted verifiable credentials.
   *
   * This method iterates through the services in the DID Document and:
   * - Extracts credentials from Linked Verifiable Presentations.
   * - Queries the Trust Registry for Verifiable Public Registries.
   */
  private async processDidServices(services: Service[]): Promise<VerifiableCredential[]> {
    const verifiableCredentials: VerifiableCredential[] = []

    for (const service of services) {
      if (service.type === 'LinkedVerifiablePresentation') {
        const credential = await this.extractCredentialFromVP(service)
        if (credential) verifiableCredentials.push(credential)
      } else if (service.type === 'VerifiablePublicRegistry') {
        await this.queryTrustRegistry(service)
      }
    }

    return verifiableCredentials
  }

  /**
   * Checks the Trust Registry to verify if the DID is an authorized issuer.
   *
   * @param {string} did - The Decentralized Identifier (DID) to be checked.
   * @param {DidDocument} didDocument - The resolved DID Document.
   * @returns {Promise<ResolveResult>} A result indicating whether the DID is valid.
   *
   * This method performs the following steps:
   * 1. Requests the Trust Registry to check if the DID is authorized.
   * 2. If authorized, retrieves the associated credential schema.
   * 3. Validates the schema against the expected types (ECS.ORG, ECS.PERSON).
   * 4. Returns the validation result along with the DID Document.
   */
  private async checkTrustRegistry(did: string, didDocument: DIDDocument): Promise<ResolveResult> {
    try {
      const permResponse = await fetch(`${this.trustRegistryUrl}/prem/v1/get`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ did }),
      })

      if (!permResponse.ok) return { result: false, didDocument }
      const permission: Permission = (await permResponse.json()) as Permission

      if (permission.type !== PermissionType.ISSUER) return { result: false, didDocument }

      const schemaResponse = await fetch(`${this.trustRegistryUrl}/cs/v1/get`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: permission.schema_id }),
      })

      if (!schemaResponse.ok) return { result: false, didDocument }
      const credentialSchema: CredentialSchema = (await schemaResponse.json()) as CredentialSchema

      const schemaType = checkSchemaMatch(credentialSchema.json_schema as ECS)
      return { result: schemaType !== null && [ECS.ORG, ECS.PERSON].includes(schemaType), didDocument }
    } catch (error) {
      return { result: false, message: `Error checking trust registry: ${error}` }
    }
  }

  /**
   * Fetches and validates a DID Document.
   * @param did - The DID to fetch.
   * @returns A promise resolving to the resolution result.
   */
  private async retrieveDidDocument(did: string): Promise<ResolveResult> {
    const resolutionResult = await this.resolverInstance.resolve(did)
    const didDocument = resolutionResult?.didDocument
    if (!didDocument) return { result: false, message: `DID resolution failed for ${did}` }

    const serviceEntries = didDocument.service || []
    if (!serviceEntries.length)
      return { result: false, didDocument, message: 'No services found in the DID Document.' }

    // Validate presence of "vpr-schemas"
    const hasLinkedPresentation = serviceEntries.some(
      s => s.type === 'LinkedVerifiablePresentation' && s.id.includes('#vpr-schemas'),
    )
    const hasTrustRegistry = serviceEntries.some(
      s => s.type === 'VerifiablePublicRegistry' && s.id.includes('#vpr-schemas-trust-registry'),
    )

    // Validate presence of "vpr-essential-schemas"
    const hasEssentialSchemas = serviceEntries.some(
      s => s.type === 'LinkedVerifiablePresentation' && s.id.includes('#vpr-essential-schemas'),
    )
    const hasEssentialTrustRegistry = serviceEntries.some(
      s => s.type === 'VerifiablePublicRegistry' && s.id.includes('#vpr-essential-schemas-trust-registry'),
    )

    // Validate schema consistency
    if (hasLinkedPresentation && !hasTrustRegistry) {
      throw new Error("Missing 'VerifiablePublicRegistry' entry for existing '#vpr-schemas-trust-registry'.")
    }
    if (hasTrustRegistry && !hasLinkedPresentation) {
      throw new Error("Missing 'LinkedVerifiablePresentation' entry for existing '#vpr-schemas'.")
    }
    if (hasEssentialSchemas && !hasEssentialTrustRegistry) {
      throw new Error("Missing 'VerifiablePublicRegistry' entry for existing '#vpr-essential-schemas'.")
    }
    if (hasEssentialTrustRegistry && !hasEssentialSchemas) {
      throw new Error(
        "Missing 'LinkedVerifiablePresentation' entry for existing '#vpr-essential-schemas-trust-registry'.",
      )
    }

    return { result: true, didDocument }
  }

  /**
   * Resolves a Linked Verifiable Presentation (VP) from a service endpoint.
   * @param service - The service containing the VP.
   * @returns A promise resolving to the verifiable credential.
   */
  private async extractCredentialFromVP(service: Service): Promise<VerifiableCredential> {
    const endpoints = Array.isArray(service.serviceEndpoint)
      ? service.serviceEndpoint
      : [service.serviceEndpoint]
    const validEndpoints = endpoints.filter(ep => typeof ep === 'string') as string[]
    if (!validEndpoints.length) throw new Error('No valid endpoints found')

    for (const endpoint of validEndpoints) {
      try {
        const response = await fetch(endpoint)
        if (response.ok) {
          const vp = (await response.json()) as VerifiablePresentation
          const credential = await this.getVerifiedCredential(vp) // TODO: handle many verifiableCredential??
          return await this.checkCredentialSchema(credential)
        }
        throw new Error(`Error fetching VP from ${endpoint}: ${response.statusText}`)
      } catch (error) {
        throw new Error(`Failed to fetch VP from ${endpoint}: ${error}`)
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
    if (
      !service.serviceEndpoint ||
      !Array.isArray(service.serviceEndpoint) ||
      service.serviceEndpoint.length === 0
    ) {
      throw new Error('The service does not have a valid endpoint.')
    }

    try {
      const response = await fetch(service.serviceEndpoint[0], { method: 'GET' })

      if (!response.ok) {
        throw new Error(`The service responded with code ${response.status}.`)
      }
    } catch (error) {
      throw new Error(`Error querying the Trust Registry: ${error.message}`)
    }
  }

  /**
   * Extracts a valid verifiable credential from a Verifiable Presentation.
   * @param vp - The Verifiable Presentation to parse.
   * @returns A valid Verifiable Credential.
   * @throws Error if no valid credential is found.
   */
  private async getVerifiedCredential(vp: VerifiablePresentation): Promise<VerifiableCredential> {
    if (!vp.verifiableCredential || vp.verifiableCredential.length === 0) {
      throw new Error('No verifiable credential found in the response')
    }
    const validCredential = vp.verifiableCredential.find(vc => vc.type.includes('VerifiableCredential')) as
      | VerifiableCredential
      | undefined
    if (!validCredential) {
      throw new Error('No valid verifiable credential found in the response')
    }
    const isVerified = await verifyLinkedVP(validCredential);
    if (!isVerified) {
      throw new Error("The verifiable credential proof is not valid.");
    }

    return validCredential
  }

  /**
   * Validates a Verifiable Credential's schema against expected trust criteria.
   * @param credential - The Verifiable Credential to validate.
   * @returns A promise resolving to the validated Verifiable Credential.
   * @throws Error if validation fails.
   */
  private async checkCredentialSchema(credential: VerifiableCredential): Promise<VerifiableCredential> {
    const { credentialSchema, credentialSubject } = credential
    if (!credentialSchema || !credentialSubject) {
      throw new Error("Missing 'credentialSchema' or 'credentialSubject' in Verifiable Trust Credential.")
    }

    const schema = Array.isArray(credentialSchema) ? credentialSchema[0] : credentialSchema
    let subject = Array.isArray(credentialSubject) ? credentialSubject[0] : credentialSubject
    const { id, type } = schema as Record<string, any>
    if (!id?.startsWith('http') || type !== 'JsonSchemaCredential') {
      throw new Error(
        "Invalid credential schema: id must be a valid URL and type must be 'JsonSchemaCredential'.",
      )
    }

    try {
      // Check credential
      const schemaResponse = await fetch(id)
      if (!schemaResponse.ok) throw new Error(`Failed to fetch schema from ${id}`)
      const schemaData = (await schemaResponse.json()) as CredentialSchema
      // Check Schema
      const refUrl =
        subject && typeof subject === 'object' && 'jsonSchema' in subject && (subject as any).jsonSchema?.$ref
      if (refUrl) {
        const refResponse = await fetch(refUrl)
        if (!refResponse.ok) throw new Error(`Failed to fetch referenced schema from ${refUrl}`)
        subject = (await refResponse.json()) as JsonLdObject
      }

      const schemaObject = JSON.parse(schemaData.json_schema)
      const ajv = new Ajv()
      addFormats(ajv)
      const validate: ValidateFunction = ajv.compile(schemaObject)

      if (!validate(subject)) {
        throw new Error(`Credential does not conform to schema: ${JSON.stringify(validate.errors)}`)
      }
      return credential
    } catch (error) {
      throw new Error(`Failed to validate credential: ${error.message}`)
    }
  }
}
