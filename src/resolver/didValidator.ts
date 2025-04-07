import type {
  W3cVerifiableCredential,
  W3cPresentation,
  W3cJsonLdVerifiablePresentation,
  W3cJsonLdVerifiableCredential,
} from '@credo-ts/core'

import { DIDDocument, Resolver, Service } from 'did-resolver'
import * as didWeb from 'web-did-resolver'

import {
  CredentialSchema,
  ECS,
  Permission,
  PermissionType,
  ResolverConfig,
  TrustedResolution,
  TrustErrorCode,
  IService,
  ICredential,
} from '../types'
import {
  buildMetadata,
  checkSchemaMatch,
  fetchSchema,
  handleTrustError,
  identifySchema,
  TrustError,
  validateSchemaContent,
  verifyDigestSRI,
  verifySignature,
} from '../utils'

// Generic resolver for DID Web only
const resolverInstance = new Resolver(didWeb.getResolver())

/**
 * Resolves a DID, validates its document, and associated services.
 * Retrieves the DID document, processes its verifiable credentials, and checks its trust status.
 * @param did - The DID to resolve.
 * @param options - Configuration options for the resolver, including the trust registry URL.
 * @returns A promise that resolves to the trust resolution.
 */
export async function resolve(did: string, options: ResolverConfig): Promise<TrustedResolution> {
  if (!did) {
    return { metadata: buildMetadata(TrustErrorCode.INVALID, 'Invalid DID URL') }
  }

  const { trustRegistryUrl, didResolver } = options
  try {
    const didDocument = await retrieveDidDocument(did, didResolver)

    try {
      return await processDidDocument(did, didDocument, trustRegistryUrl)
    } catch (error) {
      return handleTrustError(error, didDocument)
    }
  } catch (error) {
    return handleTrustError(error)
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
async function processDidDocument(
  did: string,
  didDocument: DIDDocument,
  trustRegistryUrl: string,
): Promise<TrustedResolution> {
  if (!didDocument?.service)
    throw new TrustError(TrustErrorCode.NOT_FOUND, 'Failed to retrieve DID Document with service.')

  const credentials: ICredential[] = []
  let issuerCredential: ICredential | undefined
  let verifiableService: IService | undefined

  await Promise.all(
    didDocument.service.map(async service => {
      if (service.type === 'LinkedVerifiablePresentation') {
        const vp = await extractCredentialFromVP(service)
        if (vp) {
          const credential = await getVerifiedCredential(vp)
          credentials.push(credential)
          const issuer = Array.isArray(vp.verifiableCredential)
            ? (vp.verifiableCredential[0] as W3cJsonLdVerifiableCredential)?.issuer
            : (vp.verifiableCredential as W3cJsonLdVerifiableCredential)?.issuer
          if ([ECS.ORG, ECS.PERSON].includes(credential.type as ECS) && issuer === did)
            issuerCredential = credential
          if (ECS.SERVICE === credential.type) verifiableService = credential as IService
        }
      }
      if (service.type === 'VerifiablePublicRegistry') await queryTrustRegistry(service)
      return service
    }),
  )

  // If proof of trust exists, return the result with the verifiableService (issuer equals did)
  if (issuerCredential && verifiableService)
    return { didDocument, metadata: buildMetadata(), issuerCredential, verifiableService }
  if (!issuerCredential && verifiableService) {
    // Otherwise, check the trust registry
    return checkTrustRegistry(did, didDocument, trustRegistryUrl, verifiableService)
  }
  throw new TrustError(
    TrustErrorCode.NOT_FOUND,
    'Valid issuerCredential and verifiableService were not found',
  )
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
  didDocument: DIDDocument,
  trustRegistryUrl: string,
  verifiableService?: IService,
): Promise<TrustedResolution> {
  try {
    const permResponse = await fetch(`${trustRegistryUrl}/prem/v1/get`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ did }),
    })

    if (!permResponse.ok)
      return {
        didDocument,
        metadata: buildMetadata(TrustErrorCode.NOT_FOUND, 'No data found in the trust registry.'),
      }
    const permission: Permission = (await permResponse.json()) as Permission

    if (permission.type !== PermissionType.ISSUER)
      return {
        didDocument,
        metadata: buildMetadata(TrustErrorCode.INVALID_ISSUER, 'The provided DID is not a valid issuer.'),
      }

    const schemaResponse = await fetch(`${trustRegistryUrl}/cs/v1/get`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: permission.schema_id }),
    })

    if (!schemaResponse.ok)
      return {
        didDocument,
        metadata: buildMetadata(
          TrustErrorCode.INVALID_REQUEST,
          `HTTP error ${schemaResponse.status}: Request to trust registry failed.`,
        ),
      }
    const credentialSchema: CredentialSchema = (await schemaResponse.json()) as CredentialSchema

    const schemaType = checkSchemaMatch(credentialSchema.json_schema as ECS)
    const isValid = schemaType !== null && [ECS.ORG, ECS.PERSON].includes(schemaType)
    return {
      didDocument,
      metadata: isValid
        ? buildMetadata()
        : buildMetadata(TrustErrorCode.INVALID, 'Schema type does not match.'),
      verifiableService,
    } // TODO: where is the credential subject for 'issuerCredential'??
  } catch (error) {
    return { metadata: buildMetadata(TrustErrorCode.INVALID, `Error checking trust registry: ${error}.`) }
  }
}

/**
 * Fetches and validates a DID Document.
 * @param did - The DID to fetch.
 * @returns A promise resolving to the resolution result.
 */
async function retrieveDidDocument(did: string, didResolver?: Resolver): Promise<DIDDocument> {
  const resolutionResult = await (didResolver?.resolve(did) ?? resolverInstance.resolve(did))
  const didDocument = resolutionResult?.didDocument
  if (!didDocument) throw new TrustError(TrustErrorCode.NOT_FOUND, `DID resolution failed for ${did}`)

  const serviceEntries = didDocument.service || []
  if (!serviceEntries.length)
    throw new TrustError(TrustErrorCode.NOT_FOUND, 'No services found in the DID Document.')

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
    throw new TrustError(
      TrustErrorCode.INVALID,
      "Missing 'VerifiablePublicRegistry' entry for existing '#vpr-schemas-trust-registry'.",
    )
  }
  if (hasTrustRegistry && !hasLinkedPresentation) {
    throw new TrustError(
      TrustErrorCode.INVALID,
      "Missing 'LinkedVerifiablePresentation' entry for existing '#vpr-schemas'.",
    )
  }
  if (hasEssentialSchemas && !hasEssentialTrustRegistry) {
    throw new TrustError(
      TrustErrorCode.INVALID,
      "Missing 'VerifiablePublicRegistry' entry for existing '#vpr-essential-schemas'.",
    )
  }
  if (hasEssentialTrustRegistry && !hasEssentialSchemas) {
    throw new TrustError(
      TrustErrorCode.INVALID,
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
async function extractCredentialFromVP(service: Service): Promise<W3cPresentation> {
  const endpoints = Array.isArray(service.serviceEndpoint)
    ? service.serviceEndpoint
    : [service.serviceEndpoint]
  const validEndpoints = endpoints.filter(ep => typeof ep === 'string') as string[]
  if (!validEndpoints.length) throw new TrustError(TrustErrorCode.NOT_FOUND, 'No valid endpoints found')

  for (const endpoint of validEndpoints) {
    try {
      return await fetchSchema<W3cPresentation>(endpoint)
    } catch (error) {
      throw new TrustError(TrustErrorCode.INVALID_REQUEST, `Failed to fetch VP from ${endpoint}: ${error}`)
    }
  }
  throw new TrustError(TrustErrorCode.INVALID, 'No valid endpoints found')
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
    throw new TrustError(TrustErrorCode.INVALID, 'The service does not have a valid endpoint.')
  }

  try {
    const response = await fetch(service.serviceEndpoint[0], { method: 'GET' })

    if (!response.ok) {
      throw new TrustError(
        TrustErrorCode.INVALID_REQUEST,
        `The service responded with code ${response.status}.`,
      )
    }
  } catch (error) {
    throw new TrustError(
      TrustErrorCode.INVALID_REQUEST,
      `Error querying the Trust Registry: ${error.message}`,
    )
  }
}

/**
 * Extracts a valid verifiable credential from a Verifiable Presentation.
 * @param vp - The Verifiable Presentation to parse.
 * @returns A valid Verifiable Credential.
 * @throws Error if no valid credential is found.
 */
async function getVerifiedCredential(vp: W3cPresentation): Promise<ICredential> {
  if (
    !vp.verifiableCredential ||
    !Array.isArray(vp.verifiableCredential) ||
    vp.verifiableCredential.length === 0
  ) {
    throw new TrustError(TrustErrorCode.NOT_FOUND, 'No verifiable credential found in the response')
  }
  const validCredential = vp.verifiableCredential.find(vc => vc.type.includes('VerifiableCredential')) as
    | W3cVerifiableCredential
    | undefined
  if (!validCredential) {
    throw new TrustError(TrustErrorCode.INVALID, 'No valid verifiable credential found in the response')
  }
  const isVerified = await verifySignature(vp as W3cJsonLdVerifiablePresentation)
  if (!isVerified) {
    throw new TrustError(TrustErrorCode.INVALID, 'The verifiable credential proof is not valid.')
  }

  return await processCredential(validCredential)
}

/**
 * Processes and validates a Verifiable Credential against its declared schema.
 *
 * This function supports two schema types:
 * - 'JsonSchemaCredential': A credential that references another credential as its schema.
 * - 'JsonSchema': A credential that uses a raw JSON Schema for validation.
 *
 * Validation includes:
 * - Checking required fields (`credentialSchema`, `credentialSubject`)
 * - Verifying the schema type
 * - Fetching the schema and subject schema (if needed)
 * - Validating schema integrity via SRI
 * - Validating the credential against the schema definitions
 *
 * @param credential - The Verifiable Credential to validate.
 * @param attrs - Optional attributes to validate against the credential subject schema.
 * @returns A Promise resolving to the processed and validated credential.
 * @throws {TrustError} If validation fails due to missing fields, unsupported types, schema mismatch, or integrity check failure.
 */
async function processCredential(
  credential: W3cVerifiableCredential,
  attrs?: Record<string, string>,
): Promise<ICredential> {
  const { credentialSchema, credentialSubject } = credential
  if (!credentialSchema || !credentialSubject) {
    throw new TrustError(
      TrustErrorCode.NOT_FOUND,
      "Missing 'credentialSchema' or 'credentialSubject' in Verifiable Trust Credential.",
    )
  }
  const schema = Array.isArray(credentialSchema) ? credentialSchema[0] : credentialSchema
  const subject = Array.isArray(credentialSubject) ? credentialSubject[0] : credentialSubject

  if (!['JsonSchemaCredential', 'JsonSchema'].includes(schema.type))
    throw new TrustError(
      TrustErrorCode.INVALID,
      "Credential schema type must be 'JsonSchemaCredential' or 'JsonSchema'.",
    )
  if (schema.type === 'JsonSchemaCredential') {
    const jsonSchemaCredential = await fetchSchema<W3cVerifiableCredential>(schema.id)
    return processCredential(jsonSchemaCredential, subject as Record<string, string>)
  }

  if (schema.type === 'JsonSchema') {
    const { digestSRI: schemaDigestSRI } = schema as Record<string, any>
    const { digestSRI: subjectDigestSRI } = subject as Record<string, any>
    try {
      // Fetch and verify the credential schema integrity
      const schemaData = await fetchSchema(schema.id)
      verifyDigestSRI(JSON.stringify(schemaData), schemaDigestSRI, 'Credential Schema')

      // Validate the credential against the schema
      validateSchemaContent(schemaData, credential)

      // Extract the reference URL from the subject if it contains a JSON Schema reference
      const refUrl =
        subject && typeof subject === 'object' && 'jsonSchema' in subject && (subject as any).jsonSchema?.$ref

      // If a reference URL exists, fetch the referenced schema
      const subjectSchema = await fetchSchema<CredentialSchema>(refUrl)
      // Verify the integrity
      verifyDigestSRI(JSON.stringify(subjectSchema), subjectDigestSRI, 'Credential Subject')
      validateSchemaContent(JSON.parse(subjectSchema.json_schema), attrs)
      return { type: identifySchema(attrs), credentialSubject: attrs } as ICredential
    } catch (error) {
      throw new TrustError(TrustErrorCode.INVALID, `Failed to validate credential: ${error.message}`)
    }
  }
  throw new TrustError(TrustErrorCode.VERIFICATION_FAILED, 'Failed to validate credential')
}
