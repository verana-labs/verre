import { JsonLdObject, VerifiableCredential, VerifiablePresentation } from '@transmute/verifiable-credentials'
import Ajv, { ValidateFunction } from 'ajv/dist/2020'
import addFormats from 'ajv-formats'
import { DIDDocument, Resolver, Service } from 'did-resolver'
import * as didWeb from 'web-did-resolver'

import {
  CredentialSchema,
  DidDocumentResult,
  DIDDocumentResolved,
  ECS,
  Permission,
  PermissionType,
  ResolverConfig,
  ResolveResult,
  ServiceWithCredential,
} from '../types'
import { checkSchemaMatch, identifySchema, verifyLinkedVP } from '../utils'

const resolverInstance = new Resolver(didWeb.getResolver())
const defaultOptions: Required<ResolverConfig> = {
  trustRegistryUrl: 'http://testTrust.org', // TODO: check this URL
}

/**
 * Resolves a DID and validates its document and associated services.
 * @param did - The DID to resolve.
 * @returns A promise resolving to the resolution result.
 */
export async function resolve(did: string, options: ResolverConfig = {}): Promise<ResolveResult> {
  if (!did) return { result: false, message: 'Invalid DID URL' }
  const { trustRegistryUrl } = { ...defaultOptions, ...options }

  try {
    const didDocument = await retrieveDidDocument(did)
    const { verifiableCredentials, didDocumentResolved } = await processDidDocument(didDocument)
    const isValid = verifiableCredentials.some(vc => {
      const schema = identifySchema(vc.credentialSubject)
      return vc.issuer === did && schema !== null && [ECS.ORG, ECS.PERSON].includes(schema)
    })

    if (!isValid) {
      return checkTrustRegistry(did, didDocumentResolved, trustRegistryUrl)
    }

    return { result: isValid, didDocumentResolved }
  } catch (error) {
    return { result: false, message: `Error resolving DID Document: ${error}` }
  }
}

/**
 * Processes a DID Document to extract verifiable credentials, verifiable presentations,
 * and updated services.
 *
 * @param {DIDDocument} didDocument - The DID Document containing services.
 * @returns {Promise<DidDocumentResult>} An object containing verifiable credentials,
 *          verifiable presentations, and the updated list of services.
 *
 * This method iterates through the services in the DID Document and:
 * - Extracts credentials from Linked Verifiable Presentations.
 * - Queries the Trust Registry for Verifiable Public Registries.
 * - Collects the updated list of services, including those with extracted credentials.
 *
 * Note: If a Verifiable Presentation contains multiple credentials, only the first one is processed.
 */
async function processDidDocument(didDocument: DIDDocument): Promise<DidDocumentResult> {
  if (!didDocument?.service) throw new Error('Failed to retrieve DID Document with service.')

  const verifiableCredentials: VerifiableCredential[] = []
  const newServices = await Promise.all(
    didDocument.service.map(async service => {
      if (service.type === 'LinkedVerifiablePresentation') {
        const serviceWithVP = await extractCredentialFromVP(service)
        if (serviceWithVP.verifiablePresentation) {
          verifiableCredentials.push(await getVerifiedCredential(serviceWithVP.verifiablePresentation))
        }
        return serviceWithVP
      }
      if (service.type === 'VerifiablePublicRegistry') await queryTrustRegistry(service)
      return service
    }),
  )

  return { verifiableCredentials, didDocumentResolved: { ...didDocument, service: newServices } }
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
async function checkTrustRegistry(
  did: string,
  didDocumentResolved: DIDDocumentResolved,
  trustRegistryUrl: string,
): Promise<ResolveResult> {
  try {
    const permResponse = await fetch(`${trustRegistryUrl}/prem/v1/get`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did }),
    })

    if (!permResponse.ok) return { result: false, didDocumentResolved }
    const permission: Permission = (await permResponse.json()) as Permission

    if (permission.type !== PermissionType.ISSUER) return { result: false, didDocumentResolved }

    const schemaResponse = await fetch(`${trustRegistryUrl}/cs/v1/get`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: permission.schema_id }),
    })

    if (!schemaResponse.ok) return { result: false, didDocumentResolved }
    const credentialSchema: CredentialSchema = (await schemaResponse.json()) as CredentialSchema

    const schemaType = checkSchemaMatch(credentialSchema.json_schema as ECS)
    return { result: schemaType !== null && [ECS.ORG, ECS.PERSON].includes(schemaType), didDocumentResolved }
  } catch (error) {
    return { result: false, message: `Error checking trust registry: ${error}` }
  }
}

/**
 * Fetches and validates a DID Document.
 * @param did - The DID to fetch.
 * @returns A promise resolving to the resolution result.
 */
async function retrieveDidDocument(did: string): Promise<DIDDocument> {
  const resolutionResult = await resolverInstance.resolve(did)
  const didDocument = resolutionResult?.didDocument
  if (!didDocument) throw new Error(`DID resolution failed for ${did}`)

  const serviceEntries = didDocument.service || []
  if (!serviceEntries.length) throw new Error('No services found in the DID Document.')

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

  return didDocument
}

/**
 * Extracts a Linked Verifiable Presentation (VP) from a service endpoint.
 *
 * This function retrieves a Verifiable Presentation from the provided service's
 * endpoint(s). It filters out invalid endpoints, attempts to fetch the VP, and
 * returns the service enriched with the retrieved VP.
 *
 * @param service - The service containing the endpoint(s) pointing to a Verifiable Presentation.
 * @returns A promise resolving to the service with an attached Verifiable Presentation.
 * @throws An error if no valid endpoints are found or if the request fails.
 */
async function extractCredentialFromVP(service: Service): Promise<ServiceWithCredential> {
  const endpoints = Array.isArray(service.serviceEndpoint)
    ? service.serviceEndpoint
    : [service.serviceEndpoint]
  const validEndpoints = endpoints.filter(ep => typeof ep === 'string') as string[]
  if (!validEndpoints.length) throw new Error('No valid endpoints found')

  for (const endpoint of validEndpoints) {
    try {
      const response = await fetch(endpoint)
      if (response.ok) {
        const verifiablePresentation = (await response.json()) as VerifiablePresentation
        return { ...service, verifiablePresentation }
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
async function queryTrustRegistry(service: Service) {
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
async function getVerifiedCredential(vp: VerifiablePresentation): Promise<VerifiableCredential> {
  if (!vp.verifiableCredential || vp.verifiableCredential.length === 0) {
    throw new Error('No verifiable credential found in the response')
  }
  const validCredential = vp.verifiableCredential.find(vc => vc.type.includes('VerifiableCredential')) as
    | VerifiableCredential
    | undefined
  if (!validCredential) {
    throw new Error('No valid verifiable credential found in the response')
  }
  const isVerified = await verifyLinkedVP(validCredential)
  if (!isVerified) {
    throw new Error('The verifiable credential proof is not valid.')
  }

  return await checkCredentialSchema(validCredential)
}

/**
 * Validates a Verifiable Credential's schema against expected trust criteria.
 * @param credential - The Verifiable Credential to validate.
 * @returns A promise resolving to the validated Verifiable Credential.
 * @throws Error if validation fails.
 */
async function checkCredentialSchema(credential: VerifiableCredential): Promise<VerifiableCredential> {
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
    const ajv = new Ajv({ strict: false })
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
