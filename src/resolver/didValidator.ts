import {
  type W3cVerifiableCredential,
  type W3cPresentation,
  type W3cJsonLdVerifiablePresentation,
  type AgentContext,
  JsonObject,
  W3cCredentialSubject,
  DidsApi,
  ConsoleLogger,
} from '@credo-ts/core'
import { DIDDocument, Resolver, Service } from 'did-resolver'
import * as didWeb from 'web-did-resolver'

import {
  ECS,
  ResolverConfig,
  TrustResolution,
  TrustErrorCode,
  IService,
  ICredential,
  IOrg,
  IPerson,
  InternalResolverConfig,
  Permission,
  VerifiablePublicRegistry,
  TrustResolutionOutcome,
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
const logger = new ConsoleLogger()

/**
 * Resolves a Decentralized Identifier (DID) and performs trust validation.
 *
 * This is the main entrypoint for resolving a DID. It retrieves the DID Document,
 * validates its structure, and checks the trust status of the identifier and its services
 * using the provided verifiable public registry.
 *
 * @param input - A DID string (e.g., did:key:..., did:web:...) or a W3C JSON-LD Verifiable Credential. Any other input type will be rejected
 * @param options - Configuration options for the resolver.
 * @param options.verifiablePublicRegistries - *(Optional)* The registry public registries URIs used to validate the DID and its services.
 * @param options.didResolver - *(Optional)* A custom DID resolver instance to override the default resolver behavior.
 * @param options.agentContext - The agent context containing the global operational state of the agent, including registered services, modules, dids, wallets, storage, and configuration from Credo-TS.
 *
 * @returns A promise that resolves to a `TrustResolution` object containing the resolution result,
 * DID document metadata, and trust validation outcome.
 */
export async function resolve(
  input: string | W3cVerifiableCredential,
  options: ResolverConfig,
): Promise<TrustResolution> {
  if (!options.didResolver) {
    options.didResolver = getCredoTsDidResolver(options.agentContext)
  }

  if (typeof input === 'string') return await _resolve(input, options)
  if (typeof input === 'object' && input !== null && 'credentialSubject' in input) {
    return await _resolveCredential(input, options)
  }

  throw new TrustError(
    TrustErrorCode.NOT_SUPPORTED,
    'Unsupported input: only DID strings or W3C JSON-LD Verifiable Credentials are allowed.',
  )
}

/**
 * Creates a DID Resolver instance that uses the Credo-TS internal `DidResolverService`
 * to resolve Decentralized Identifiers (DIDs).
 *
 * This resolver delegates all resolution requests to the `DidResolverService` registered
 * within the provided `AgentContext`.
 *
 * @param agentContext - The agent context containing the global operational state
 * of the agent, including registered services, modules, DIDs, wallets, storage, and configuration
 * from Credo-TS.
 *
 * @returns A `did-resolver` `Resolver` instance configured to use Credo-TS for DID resolution.
 */
function getCredoTsDidResolver(agentContext: AgentContext): Resolver {
  const didResolverApi = agentContext.dependencyManager.resolve(DidsApi)
  return new Resolver(
    new Proxy(
      {},
      {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        get: (_target, _method: string) => {
          return async (did: string) => didResolverApi.resolve(did)
        },
      },
    ),
  )
}

/**
 * @deprecated This function is deprecated and will be removed in an upcoming version.
 * Verifies the authorization of a DID by resolving linked services,
 * extracting verifiable credentials, and checking permissions from the trust registry.
 *
 * @param did - The Decentralized Identifier to be verified.
 * @returns A list of resolved permissions or nulls for each valid service.
 */
export async function verifyDidAuthorization(did: string) {
  const didDocument = await retrieveDidDocument(did)

  const results = await Promise.all(
    (didDocument?.service ?? [])
      .filter(service => service.type === 'LinkedVerifiablePresentation' && service.id?.includes('org'))
      .map(service => resolvePermissionFromService(service, did)),
  )

  return results
}

/**
 * Resolves a permission for a given service by extracting and following
 * the chain of linked credentials, schemas, and trust registry queries.
 *
 * @param service - A DID Document service entry of type 'LinkedVerifiablePresentation'.
 * @param did - The original DID whose authorization is being verified.
 * @returns The resolved permission object or null if resolution fails.
 */
async function resolvePermissionFromService(service: Service, did: string): Promise<Permission | null> {
  try {
    const vp = await resolveServiceVP(service)
    const credential = resolveCredential(vp)
    const { schema } = resolveSchemaAndSubject(credential)

    const schemaCredential = await fetchJson<W3cVerifiableCredential>(schema.id)
    const { subject } = resolveSchemaAndSubject(schemaCredential)

    const refUrl = getRefUrl(subject)
    // Extract schema ID and trust registry base
    const { trustRegistry, schemaId } = resolveTrustRegistry(refUrl)

    const permUrl = `${toIndexerUrl(trustRegistry)}/perm/v1/list?did=${encodeURIComponent(
      did,
    )}&type=ISSUER&response_max_size=1&schema_id=${schemaId}`

    return await fetchJson<Permission>(permUrl)
  } catch (error) {
    logger.error(`Error processing service: ${service}`, error)
    return null
  }
}

export async function _resolveCredential(
  input: W3cVerifiableCredential,
  options: ResolverConfig,
): Promise<TrustResolution> {
  let issuerDid: string | undefined
  const { verifiablePublicRegistries, didResolver } = options
  if (typeof input.issuer === 'string') {
    issuerDid = input.issuer
  } else if (input.issuer && typeof input.issuer === 'object' && 'id' in input.issuer) {
    issuerDid = input.issuer.id
  } else {
    throw new TrustError(
      TrustErrorCode.INVALID_ISSUER,
      'The credential issuer is not a valid DID or supported issuer format',
    )
  }
  const didDocument = await retrieveDidDocument(issuerDid, didResolver)
  const { credential, outcome } = await processCredential(input, verifiablePublicRegistries ?? [], issuerDid)

  const service = credential.schemaType === ECS.SERVICE ? credential : undefined
  return { didDocument, verified: true, outcome, service }
}

/**
 * Extracts the Trust Registry base URL and the schema ID from a given schema `refUrl`.
 *
 * Example:
 * Input:  "https://registry.example.com/schemas/v1/1"
 * Output: {
 *   trustRegistry: "https://registry.example.com/schemas",
 *   schemaId: "1"
 * }
 *
 * @param refUrl The reference URL pointing to a schema within a Trust Registry.
 * @returns An object containing the `trustRegistry` base URL and the `schemaId`.
 */
export function resolveTrustRegistry(
  refUrl: string,
  verifiablePublicRegistries?: VerifiablePublicRegistry[],
): { trustRegistry: string; schemaId: string; outcome: TrustResolutionOutcome; schemaUrl: string } {
  const registry = verifiablePublicRegistries?.find(registry => refUrl.startsWith(registry.id))
  const schemaUrl =
    registry?.id && registry.id[0] ? refUrl.replace(registry.id, registry.baseUrls[0]) : refUrl
  const urlObj = new URL(schemaUrl)
  const segments = urlObj.pathname.split('/').filter(Boolean)
  const outcome = !registry
    ? TrustResolutionOutcome.NOT_TRUSTED
    : registry.production
      ? TrustResolutionOutcome.VERIFIED
      : TrustResolutionOutcome.VERIFIED_TEST

  return {
    trustRegistry: `${urlObj.origin}/${segments[0]}`,
    schemaId: segments.at(-1)!,
    outcome,
    schemaUrl,
  }
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
    return {
      verified: false,
      outcome: TrustResolutionOutcome.INVALID,
      metadata: buildMetadata(TrustErrorCode.INVALID, 'Invalid DID URL'),
    }
  }

  const { verifiablePublicRegistries, didResolver, attrs, agentContext } = options
  try {
    const didDocument = await retrieveDidDocument(did, didResolver)

    try {
      return await processDidDocument(
        did,
        didDocument,
        agentContext,
        verifiablePublicRegistries || [],
        didResolver,
        attrs,
      )
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
 * @param {Resolver} [didResolver] - Optional DID resolver instance for nested resolution.
 * @param {IService} [attrs] - Optional pre-identified verifiable service to use.
 * @param {VerifiablePublicRegistry[]} verifiablePublicRegistries - The registry public registries URIs used for validation and lookup.
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
  agentContext: AgentContext,
  verifiablePublicRegistries: VerifiablePublicRegistry[],
  didResolver?: Resolver,
  attrs?: IService,
): Promise<TrustResolution> {
  if (!didDocument?.service) {
    throw new TrustError(TrustErrorCode.NOT_FOUND, 'Failed to retrieve DID Document with service.')
  }

  const credentials: ICredential[] = []
  let serviceProvider: ICredential | undefined
  let service: IService | undefined = attrs
  let outcome: TrustResolutionOutcome = TrustResolutionOutcome.NOT_TRUSTED
  const patterns = [/^vpr-schemas.*-c-vp$/, /^vpr-ecs.*-c-vp$/]

  await Promise.all(
    didDocument.service.map(async didService => {
      const { type, id } = didService
      const matchesPattern = patterns.some(pattern => pattern.test(id.split('#')[1]))
      if (type === 'LinkedVerifiablePresentation' && matchesPattern) {
        const vp = await resolveServiceVP(didService)
        if (!vp)
          throw new TrustError(
            TrustErrorCode.NOT_SUPPORTED,
            `Invalid Linked Verifiable Presentation for service id: '${id}'`,
          )

        const { credential, outcome: vpOutcome } = await getVerifiedCredential(
          vp,
          verifiablePublicRegistries,
          agentContext,
        )
        credentials.push(credential)
        outcome = vpOutcome

        const isServiceCred = credential.schemaType === ECS.SERVICE
        const isExternalIssuer = credential.issuer !== did

        if (isServiceCred && isExternalIssuer) {
          const resolution = await _resolve(credential.issuer, {
            verifiablePublicRegistries,
            didResolver,
            attrs: credential,
            agentContext,
          })
          service = resolution.service
          serviceProvider = resolution.serviceProvider
        }
      }
    }),
  )
  service ??= credentials.find((cred): cred is IService => cred.schemaType === ECS.SERVICE)
  serviceProvider ??= credentials.find(
    (cred): cred is IOrg | IPerson => cred.schemaType === ECS.ORG || cred.schemaType === ECS.PERSON,
  )

  // If proof of trust exists, return the result with the service (issuer equals did)
  if (serviceProvider && service) {
    return {
      didDocument,
      outcome,
      verified: true,
      service,
      serviceProvider,
    }
  }
  throw new TrustError(TrustErrorCode.NOT_FOUND, 'Valid serviceProvider and service were not found')
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
 * Extracts a valid verifiable credential from a Verifiable Presentation.
 * @param vp - The Verifiable Presentation to parse.
 * @param verifiablePublicRegistries - The registry public registries URLs used for validation and lookup.
 * @param agentContext - The Agent Context for signature verification.
 * @returns A valid Verifiable Credential.
 * @throws Error if no valid credential is found.
 */
async function getVerifiedCredential(
  vp: W3cPresentation,
  verifiablePublicRegistries: VerifiablePublicRegistry[],
  agentContext: AgentContext,
): Promise<{ credential: ICredential; outcome: TrustResolutionOutcome }> {
  const w3cCredential = resolveCredential(vp)
  const isVerified = await verifySignature(vp as W3cJsonLdVerifiablePresentation, agentContext)
  if (!isVerified.result) {
    throw new TrustError(
      TrustErrorCode.INVALID,
      'The verifiable credential proof is not valid with: ' + isVerified.error,
    )
  }

  return await processCredential(w3cCredential, verifiablePublicRegistries)
}

/**
 * Finds a valid Verifiable Credential inside a Verifiable Presentation.
 * @param vp - The Verifiable Presentation to search.
 * @returns The first valid Verifiable Credential.
 * @throws Error if no valid credential is found.
 */
function resolveCredential(vp: W3cPresentation): W3cVerifiableCredential {
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

  return validCredential
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
 * @param w3cCredential - The Verifiable Credential to validate.
 * @param verifiablePublicRegistries - The registry public registries URLs used for validation and lookup.
 * @param attrs - Optional attributes to validate against the credential subject schema.
 * @returns A Promise resolving to the processed and validated credential.
 * @throws {TrustError} If validation fails due to missing fields, unsupported types, schema mismatch, or integrity check failure.
 */
async function processCredential(
  w3cCredential: W3cVerifiableCredential,
  verifiablePublicRegistries: VerifiablePublicRegistry[],
  issuer?: string,
  attrs?: Record<string, string>,
): Promise<{ credential: ICredential; outcome: TrustResolutionOutcome }> {
  const { schema, subject } = resolveSchemaAndSubject(w3cCredential)
  const id = w3cCredential.id as string

  if (schema.type === 'JsonSchemaCredential') {
    const jsonSchemaCredential = await fetchJson<W3cVerifiableCredential>(schema.id)
    return processCredential(
      jsonSchemaCredential,
      verifiablePublicRegistries,
      w3cCredential.issuer as string,
      subject as Record<string, string>,
    )
  }

  if (schema.type === 'JsonSchema') {
    const { digestSRI: schemaDigestSRI } = schema as Record<string, any>
    const { digestSRI: subjectDigestSRI } = subject as Record<string, any>
    try {
      // Fetch and verify the credential schema integrity
      const schemaData = await fetchJson(schema.id)
      verifyDigestSRI(JSON.stringify(schemaData), schemaDigestSRI, 'Credential Schema')

      // Validate the credential against the schema
      validateSchemaContent(schemaData, w3cCredential)

      // Extract the reference URL from the subject if it contains a JSON Schema reference
      const refUrl = getRefUrl(subject)
      const { trustRegistry, schemaId, outcome, schemaUrl } = resolveTrustRegistry(
        refUrl,
        verifiablePublicRegistries,
      )

      // If a reference URL exists, fetch the referenced schema
      const subjectSchema = await fetchJson<JsonObject>(schemaUrl)

      // Verify the integrity of the referenced subject schema using its SRI digest
      verifyDigestSRI(JSON.stringify(subjectSchema), subjectDigestSRI, 'Credential Subject')

      // Verify the issuer permission over the schema
      verifyPermission(trustRegistry, schemaId, outcome, issuer)

      // Validate the credential subject attributes against the JSON schema content
      validateSchemaContent(JSON.parse(subjectSchema.schema as string), attrs)
      const credential = { schemaType: identifySchema(attrs), id, issuer, ...attrs } as ICredential
      return { credential, outcome }
    } catch (error) {
      throw new TrustError(TrustErrorCode.INVALID, `Failed to validate credential: ${error.message}`)
    }
  }
  throw new TrustError(TrustErrorCode.VERIFICATION_FAILED, 'Failed to validate credential')
}

/**
 * Extracts and validates the credential schema and subject from a verifiable credential.
 * Ensures the schema is of a supported type.
 *
 * @param credential - The verifiable credential to extract data from.
 * @returns An object containing the validated schema and subject.
 * @throws TrustError if the schema or subject is missing, or if the schema type is unsupported.
 */
function resolveSchemaAndSubject(credential: W3cVerifiableCredential) {
  const schema = extractSchema(credential.credentialSchema)
  const subject = extractSchema(credential.credentialSubject)

  if (!schema || !subject) {
    throw new TrustError(
      TrustErrorCode.NOT_FOUND,
      "Missing 'credentialSchema' or 'credentialSubject' in Verifiable Trust Credential.",
    )
  }

  if (!['JsonSchemaCredential', 'JsonSchema'].includes(schema.type)) {
    throw new TrustError(
      TrustErrorCode.INVALID,
      "Credential schema type must be 'JsonSchemaCredential' or 'JsonSchema'.",
    )
  }

  return { schema, subject }
}

/**
 * Extracts the `$ref` value from a subject's `jsonSchema` property, if present.
 *
 * This utility checks whether the given `subject` is an object containing a `jsonSchema`
 * property, and if so, returns the `$ref` string inside it. If the property does not
 * exist or the structure does not match, it returns `undefined`.
 *
 * @param subject - The value to inspect. Can be any type.
 * @returns The `$ref` string if found.
 * @throws {TrustError} If validation fails due to missing fields, unsupported types.
 */
function getRefUrl(subject: W3cCredentialSubject): string {
  if (
    subject &&
    typeof subject === 'object' &&
    'jsonSchema' in subject &&
    (subject as any).jsonSchema?.$ref
  ) {
    return (subject as any).jsonSchema.$ref
  }
  throw new TrustError(
    TrustErrorCode.NOT_SUPPORTED,
    'only `$ref` references are currently supported in schemas',
  )
}

function extractSchema<T>(value?: T | T[]): T | undefined {
  return Array.isArray(value) ? value[0] : value
}

async function verifyPermission(
  trustRegistry: string,
  schemaId: string,
  outcome: TrustResolutionOutcome,
  issuer?: string,
) {
  if (!issuer) {
    throw new TrustError(TrustErrorCode.NOT_FOUND, 'Issuer not found')
  }

  const permUrl = `${toIndexerUrl(trustRegistry)}/perm/v1/list?did=${encodeURIComponent(
    issuer,
  )}&type=ISSUER&response_max_size=1&schema_id=${schemaId}`

  try {
    const [perm] = await fetchJson<Permission[]>(permUrl)

    if (outcome === TrustResolutionOutcome.VERIFIED && (!perm || perm.type !== 'ISSUER')) {
      throw new TrustError(
        TrustErrorCode.INVALID_ISSUER,
        'No valid issuer permissions were found for the specified DID',
      )
    }

    if (perm?.effective_until) {
      const ts = Date.parse(perm.effective_until)
      if (isNaN(ts)) {
        throw new TrustError(TrustErrorCode.INVALID_ISSUER, 'Invalid expiration date format')
      }
    }
  } catch (error) {
    handleTrustError(error)
  }
}

/**
 * If the registry URL originates from the API (`https://api.`), this function
 * automatically switches it to the indexer (`https://idx.`) for permission resolution.
 *
 * @param registry - The trust registry URL.
 * @returns A URL pointing to the indexer when needed.
 */
function toIndexerUrl(registry: string): string {
  if (registry.startsWith('https://api.')) {
    return registry.replace('https://api.', 'https://idx.')
  }

  return registry
}
