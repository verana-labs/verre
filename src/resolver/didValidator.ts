import {
  type W3cVerifiableCredential,
  type W3cPresentation,
  type W3cJsonLdVerifiablePresentation,
  type AgentContext,
} from '@credo-ts/core'
import { DIDDocument, Resolver, Service } from 'did-resolver'
import * as didWeb from 'web-did-resolver'

import {
  CredentialSchema,
  ECS,
  Permission,
  PermissionType,
  ResolverConfig,
  TrustResolution,
  TrustErrorCode,
  IService,
  ICredential,
  IOrg,
  IPerson,
  PermissionManagementMode,
  InternalResolverConfig,
} from '../types'
import {
  buildMetadata,
  fetchJson,
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
 * Resolves a Decentralized Identifier (DID) and performs trust validation.
 *
 * This is the main entrypoint for resolving a DID. It retrieves the DID Document,
 * validates its structure, and checks the trust status of the identifier and its services
 * using the provided trust registry.
 *
 * @param did - The Decentralized Identifier to resolve (e.g., `did:key:...`, `did:web:...`, etc.).
 * @param options - Configuration options for the resolver.
 * @param options.trustRegistryUrl - The base URL of the trust registry used to validate the DID and its services.
 * @param options.didResolver - *(Optional)* A custom DID resolver instance to override the default resolver behavior.
 *
 * @returns A promise that resolves to a `TrustResolution` object containing the resolution result,
 * DID document metadata, and trust validation outcome.
 */
export async function resolve(did: string, options: ResolverConfig): Promise<TrustResolution> {
  return await _resolve(did, options)
}

/**
 * Internal resolution and trust processing logic.
 *
 * Only use this method directly if you need to customize advanced resolution behavior.
 * This function supports injecting internal attributes (`attrs`), which are used during
 * recursive calls when resolving a parent DID Document associated with the original DID.
 *
 * For most use cases, prefer using the public `resolve` function.
 *
 * @internal
 */
export async function _resolve(did: string, options: InternalResolverConfig): Promise<TrustResolution> {
  if (!did) {
    return { metadata: buildMetadata(TrustErrorCode.INVALID, 'Invalid DID URL') }
  }

  const { trustRegistryUrl, didResolver, attrs, agent } = options
  try {
    const didDocument = await retrieveDidDocument(did, didResolver)

    try {
      return await processDidDocument(did, didDocument, trustRegistryUrl, didResolver, attrs, agent)
    } catch (error) {
      return handleTrustError(error, didDocument)
    }
  } catch (error) {
    return handleTrustError(error)
  }
}

/**
 * Processes a DID Document to extract credentials and determine the associated verifiable service.
 *
 * This method iterates through the services listed in a DID Document and:
 * - Resolves and verifies credentials embedded in Linked Verifiable Presentations.
 * - Queries Verifiable Public Registries for trusted data.
 * - Determines the appropriate verifiable service based on credentials.
 *
 * It attempts to associate a trusted service with the DID either by:
 * - Resolving a service credential issued by another DID, or
 * - Falling back to a service credential included directly in the document.
 *
 * It also identifies the credential of the issuer (organization or person) if present.
 *
 * @param {string} did - The DID being processed.
 * @param {DIDDocument} didDocument - The DID Document that may include verifiable services.
 * @param {string} trustRegistryUrl - The Trust Registry URL used for validation and lookup.
 * @param {Resolver} [didResolver] - Optional DID resolver instance for nested resolution.
 * @param {IService} [attrs] - Optional pre-identified verifiable service to use.
 *
 * @returns {Promise<TrustResolution>} An object containing:
 * - The original DID Document
 * - Extracted issuer credential (organization or person)
 * - Identified verifiable service credential
 * - Metadata
 *
 * @throws {TrustError} If no supported service types are found, or if no valid credentials can be resolved.
 *
 * Notes:
 * - Only the first credential from a Verifiable Presentation is currently processed.
 * - The function supports two types of trusted resolution flows:
 *    1. Direct: When the issuer equals the DID.
 *    2. Indirect: When the service is issued by an external trusted DID and is resolvable.
 */
async function processDidDocument(
  did: string,
  didDocument: DIDDocument,
  trustRegistryUrl?: string,
  didResolver?: Resolver,
  attrs?: IService,
  agent?: AgentContext,
): Promise<TrustResolution> {
  if (!didDocument?.service) {
    throw new TrustError(TrustErrorCode.NOT_FOUND, 'Failed to retrieve DID Document with service.')
  }

  const credentials: ICredential[] = []
  let issuerCredential: ICredential | undefined
  let verifiableService: IService | undefined = attrs

  const registryService = didDocument.service.find(s => s.type === 'VerifiablePublicRegistry')
  if (!trustRegistryUrl && registryService) {
    trustRegistryUrl = await queryTrustRegistry(registryService)
  }

  if (!trustRegistryUrl) {
    throw new TrustError(
      TrustErrorCode.NOT_FOUND,
      'Missing trustRegistryUrl. You must provide it directly or via a VerifiablePublicRegistry service.',
    )
  }

  await Promise.all(
    didDocument.service.map(async service => {
      switch (service.type) {
        case 'LinkedVerifiablePresentation': {
          const vp = await resolveServiceVP(service)
          if (!vp)
            throw new TrustError(
              TrustErrorCode.NOT_SUPPORTED,
              `Invalid Linked Verifiable Presentation for service id: '${service.id}'`,
            )

          const credential = await getVerifiedCredential(vp, trustRegistryUrl, agent)
          credentials.push(credential)

          const isServiceCred = credential.type === ECS.SERVICE
          const isExternalIssuer = credential.issuer !== did

          if (isServiceCred && isExternalIssuer) {
            const resolution = await _resolve(credential.issuer, {
              trustRegistryUrl,
              didResolver,
              attrs: credential,
              agent,
            })
            verifiableService = resolution.verifiableService
            issuerCredential = resolution.issuerCredential
          }
          break
        }
        default:
          break
      }
    }),
  )
  verifiableService ??= credentials.find((cred): cred is IService => cred.type === ECS.SERVICE)
  issuerCredential ??= credentials.find(
    (cred): cred is IOrg | IPerson => cred.type === ECS.ORG || cred.type === ECS.PERSON,
  )

  // If proof of trust exists, return the result with the verifiableService (issuer equals did)
  if (issuerCredential && verifiableService) {
    return {
      didDocument,
      metadata: buildMetadata(),
      issuerCredential,
      verifiableService,
    }
  }
  throw new TrustError(
    TrustErrorCode.NOT_FOUND,
    'Valid issuerCredential and verifiableService were not found',
  )
}

/**
 * Checks whether the provided DID is a valid issuer according to a trust registry.
 *
 * Sends a POST request to the trust registry with the DID, and validates the response.
 * Throws an error if the DID is not registered or not classified as an issuer.
 *
 * @param did - The decentralized identifier (DID) to validate.
 * @param trustRegistryUrl - The base URL of the trust registry service.
 * @returns A `Permission` object if the DID is a valid issuer.
 * @throws `TrustError` with `NOT_FOUND` if the DID is not found in the registry.
 * @throws `TrustError` with `INVALID_ISSUER` if the DID is found but not an issuer.
 */
async function isValidIssuer(did: string, trustRegistryUrl: string): Promise<Permission> {
  const permission = await fetchJson<Permission>(
    `${trustRegistryUrl}/perm/v1/find_with_did?did=${encodeURIComponent(did)}`,
  )

  if (permission.type !== PermissionType.ISSUER)
    throw new TrustError(TrustErrorCode.INVALID_ISSUER, 'The provided DID is not a valid issuer.')
  return permission
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
    s => s.type === 'LinkedVerifiablePresentation' && s.id.includes('#vpr-ecs'),
  )
  const hasEssentialTrustRegistry = serviceEntries.some(
    s => s.type === 'VerifiablePublicRegistry' && s.id.includes('#vpr-ecs-trust-registry'),
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
async function resolveServiceVP(service: Service): Promise<W3cPresentation> {
  const endpoints = Array.isArray(service.serviceEndpoint)
    ? service.serviceEndpoint
    : [service.serviceEndpoint]
  if (!endpoints.length) throw new TrustError(TrustErrorCode.NOT_FOUND, 'No valid endpoints found')

  for (const endpoint of endpoints) {
    try {
      return await fetchJson<W3cPresentation>(endpoint)
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
async function queryTrustRegistry(service: Service): Promise<string> {
  let endpoint: string | undefined
  const { serviceEndpoint } = service

  if (typeof serviceEndpoint === 'string') {
    endpoint = serviceEndpoint
  } else if (Array.isArray(serviceEndpoint)) {
    endpoint = serviceEndpoint.find(e => typeof e === 'string')
  }

  if (!endpoint || typeof endpoint !== 'string') {
    throw new TrustError(TrustErrorCode.INVALID, 'The service does not have a valid string endpoint.')
  }

  return endpoint
}

/**
 * Extracts a valid verifiable credential from a Verifiable Presentation.
 * @param vp - The Verifiable Presentation to parse.
 * @returns A valid Verifiable Credential.
 * @throws Error if no valid credential is found.
 */
async function getVerifiedCredential(
  vp: W3cPresentation,
  trustRegistryUrl: string,
  agent?: AgentContext,
): Promise<ICredential> {
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
  const isVerified = await verifySignature(vp as W3cJsonLdVerifiablePresentation, agent)
  if (!isVerified) {
    throw new TrustError(TrustErrorCode.INVALID, 'The verifiable credential proof is not valid.')
  }

  return await processCredential(validCredential, trustRegistryUrl)
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
  trustRegistryUrl: string,
  attrs?: Record<string, string>,
): Promise<ICredential> {
  const schema = extractSchema(credential.credentialSchema)
  const subject = extractSchema(credential.credentialSubject)
  if (!schema || !subject) {
    throw new TrustError(
      TrustErrorCode.NOT_FOUND,
      "Missing 'credentialSchema' or 'credentialSubject' in Verifiable Trust Credential.",
    )
  }
  const issuer = credential.issuer as string

  if (!['JsonSchemaCredential', 'JsonSchema'].includes(schema.type))
    throw new TrustError(
      TrustErrorCode.INVALID,
      "Credential schema type must be 'JsonSchemaCredential' or 'JsonSchema'.",
    )
  if (schema.type === 'JsonSchemaCredential') {
    const jsonSchemaCredential = await fetchJson<W3cVerifiableCredential>(schema.id)
    return processCredential(jsonSchemaCredential, trustRegistryUrl, subject as Record<string, string>)
  }

  if (schema.type === 'JsonSchema') {
    const { digestSRI: schemaDigestSRI } = schema as Record<string, any>
    const { digestSRI: subjectDigestSRI } = subject as Record<string, any>
    try {
      // Fetch and verify the credential schema integrity
      const schemaData = await fetchJson(schema.id)
      verifyDigestSRI(JSON.stringify(schemaData), schemaDigestSRI, 'Credential Schema')

      // Validate the credential against the schema
      validateSchemaContent(schemaData, credential)

      // Extract the reference URL from the subject if it contains a JSON Schema reference
      const refUrl =
        subject && typeof subject === 'object' && 'jsonSchema' in subject && (subject as any).jsonSchema?.$ref

      // If a reference URL exists, fetch the referenced schema
      const subjectSchema = await fetchJson<CredentialSchema>(refUrl)

      // If the referenced schema isn't open, verify that the issuer has valid permission
      if (subjectSchema.issuer_perm_management_mode !== PermissionManagementMode.OPEN)
        await isValidIssuer(issuer, trustRegistryUrl)

      // Verify the integrity of the referenced subject schema using its SRI digest
      verifyDigestSRI(JSON.stringify(subjectSchema), subjectDigestSRI, 'Credential Subject')

      // Validate the credential subject attributes against the JSON schema content
      validateSchemaContent(JSON.parse(subjectSchema.json_schema), attrs)
      return { type: identifySchema(attrs), issuer, credentialSubject: attrs } as ICredential
    } catch (error) {
      throw new TrustError(TrustErrorCode.INVALID, `Failed to validate credential: ${error.message}`)
    }
  }
  throw new TrustError(TrustErrorCode.VERIFICATION_FAILED, 'Failed to validate credential')
}

function extractSchema<T>(value?: T | T[]): T | undefined {
  return Array.isArray(value) ? value[0] : value
}
