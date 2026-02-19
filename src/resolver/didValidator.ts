import {
  type W3cVerifiableCredential,
  type W3cPresentation,
  type W3cJsonLdVerifiablePresentation,
  type AgentContext,
  W3cCredentialSubject,
  DidsApi,
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
  IPersona,
  InternalResolverConfig,
  VerifiablePublicRegistry,
  TrustResolutionOutcome,
  PermissionResponse,
  CredentialResolution,
  VerifyIssuerPermissionsOptions,
  LogLevel,
  IVerreLogger,
} from '../types'
import {
  buildMetadata,
  fetchJson,
  fetchText,
  handleTrustError,
  identifySchema,
  TrustError,
  validateSchemaContent,
  verifyDigestSRI,
  verifySignature,
  VerreLogger,
} from '../utils'

// Generic resolver for DID Web only
const resolverInstance = new Resolver(didWeb.getResolver())

/**
 * Resolves a Decentralized Identifier (DID) and performs trust validation.
 *
 * This is the main entrypoint for resolving a DID. It retrieves the DID Document,
 * validates its structure, and checks the trust status of the identifier and its services
 * using the provided verifiable public registry.
 *
 * @param did - The Decentralized Identifier to resolve (e.g., `did:key:...`, `did:web:...`, etc.).
 * @param options - Configuration options for the resolver.
 * @param options.verifiablePublicRegistries - *(Optional)* The registry public registries URIs used to validate the DID and its services.
 * @param options.didResolver - *(Optional)* A custom DID resolver instance to override the default resolver behavior.
 * @param options.agentContext - The agent context containing the global operational state of the agent, including registered services, modules, dids, wallets, storage, and configuration from Credo-TS.
 * @param options.cached - *(Optional)* Indicates whether credential verification should be performed or if a previously validated result can be reused.
 * @param options.skipDigestSRICheck - *(Optional)* When true, skips verification of the credential integrity (digestSRI). Defaults to false.
 * @param options.logger - *(Optional)* Logger instance for the resolution process. Accepts any object that implements the `IVerreLogger` interface.
 * This flag applies **only to credential verification** and its value is determined by the calling service, which is responsible
 * for managing cache validity (e.g. TTL, revocation checks).
 *
 * @returns A promise that resolves to a `TrustResolution` object containing the resolution result,
 * DID document metadata, and trust validation outcome.
 */
export async function resolveDID(did: string, options: ResolverConfig): Promise<TrustResolution> {
  if (!options.didResolver) {
    options.didResolver = getCredoTsDidResolver(options.agentContext)
  }

  return await _resolve(did, options)
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
 * Verifies whether a given issuer has permission to issue a specific credential
 * according to the trust registries and schema definitions.
 *
 * @param options - Configuration object containing all required data.
 * @param options.issuer - The issuer to validate (string or object depending on implementation).
 * @param options.jsonSchemaCredentialId - URL or identifier for the JSON schema of the credential.
 * @param options.issuanceDate - The date at which the credential was issued.
 * @param options.verifiablePublicRegistries - A list of public trust registries used for validation.
 */
export async function verifyIssuerPermissions(options: VerifyIssuerPermissionsOptions) {
  const logger = options.logger ?? new VerreLogger(LogLevel.NONE)
  try {
    logger.debug('Verifying issuer permissions', { issuer: options.issuer })
    const { issuer, jsonSchemaCredentialId, issuanceDate, verifiablePublicRegistries } = options
    const credential = await fetchJson<W3cVerifiableCredential>(jsonSchemaCredentialId)
    const { subject } = resolveSchemaAndSubject(credential, logger)
    const { trustRegistry, schemaId } = resolveTrustRegistry(getRefUrl(subject), verifiablePublicRegistries)
    await verifyPermission(trustRegistry, schemaId, issuanceDate, logger, issuer)
    logger.debug('Issuer permissions verified successfully')
    return { verified: true }
  } catch (error) {
    logger.error('Issuer permissions verification failed', error)
    return { verified: false }
  }
}

/**
 * Resolves and validates a W3C Verifiable Credential by extracting and verifying
 * the issuer's DID and evaluating the credential against the configured trust registries.
 *
 * @param cred   The W3C Verifiable Credential to be resolved and assessed.
 * @param options Configuration object containing the DID resolver and the set
 *                of verifiable public registries used during trust evaluation.
 *
 * @returns A TrustResolution object containing the issuer's DID Document,
 *          the verification outcome, and any associated service information.
 */
export async function resolveCredential(
  credential: W3cVerifiableCredential,
  options: ResolverConfig,
): Promise<CredentialResolution> {
  const logger = options.logger ?? new VerreLogger(LogLevel.NONE)
  try {
    const { verifiablePublicRegistries, skipDigestSRICheck } = options
    const { credential: w3cCredential, outcome } = await processCredential(
      credential,
      verifiablePublicRegistries ?? [],
      skipDigestSRICheck,
      logger,
    )
    return { verified: true, outcome, issuer: w3cCredential.issuer }
  } catch (error) {
    const issuer = typeof credential.issuer === 'string' ? credential.issuer : (credential.issuer?.id ?? null)
    logger.error('Credential resolution failed', error)
    return { verified: false, outcome: TrustResolutionOutcome.INVALID, issuer }
  }
}

/**
 * Resolves Trust Registry metadata from a schema reference URL by identifying
 * the matching registry, deriving the normalized schema URL, and determining
 * the trust outcome.
 *
 * @param refUrl The schema reference URL to resolve.
 * @param verifiablePublicRegistries Optional list of registries used for matching and trust evaluation.
 * @returns The resolved trust registry base URL, schema ID, trust outcome, and normalized schema URL.
 */
function resolveTrustRegistry(
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
async function _resolve(did: string, options: InternalResolverConfig): Promise<TrustResolution> {
  if (!did) {
    return {
      verified: false,
      outcome: TrustResolutionOutcome.INVALID,
      metadata: buildMetadata(TrustErrorCode.INVALID, 'Invalid DID URL'),
    }
  }

  try {
    const didDocument = await retrieveDidDocument(did, options.didResolver)

    try {
      return await processDidDocument(did, didDocument, options)
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
 * @param {boolean} cached - Optional indicates whether credential verification should be performed or if a previously validated result can be reused.
 * @param {boolean} skipDigestSRICheck - Optional When true, skips verification of the credential integrity (digestSRI). Defaults to false.
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
  options: InternalResolverConfig,
): Promise<TrustResolution> {
  const logger = options.logger ?? new VerreLogger(LogLevel.NONE)
  logger.debug('Processing DID document', { did, serviceCount: didDocument?.service?.length })

  if (!didDocument?.service) {
    throw new TrustError(TrustErrorCode.NOT_FOUND, 'Failed to retrieve DID Document with service.')
  }
  const { verifiablePublicRegistries, didResolver, agentContext, attrs, skipDigestSRICheck } = options

  const credentials: ICredential[] = []
  let serviceProvider: ICredential | undefined
  let service: IService | undefined = attrs
  let outcome: TrustResolutionOutcome = TrustResolutionOutcome.NOT_TRUSTED
  const patterns = [/^vpr-schemas.*-c-vp$/, /^vpr-ecs.*-c-vp$/]

  logger.debug('Processing DID services', { serviceCount: didDocument.service.length })
  await Promise.all(
    didDocument.service.map(async didService => {
      const { type, id } = didService
      const matchesPattern = patterns.some(pattern => pattern.test(id.split('#')[1]))
      logger.debug('Evaluating DID service', { id, type, matchesPattern })
      if (type === 'LinkedVerifiablePresentation' && matchesPattern) {
        logger.debug('Resolving linked VP service', { id })
        const vp = await resolveServiceVP(didService)
        if (!vp)
          throw new TrustError(
            TrustErrorCode.NOT_SUPPORTED,
            `Invalid Linked Verifiable Presentation for service id: '${id}'`,
          )

        logger.debug('Getting verified credential from VP', { id })
        const { credential, outcome: vpOutcome } = await getVerifiedCredential(
          vp,
          verifiablePublicRegistries ?? [],
          agentContext,
          logger,
          skipDigestSRICheck,
          options.cached,
        )
        credentials.push(credential)
        outcome = vpOutcome

        const isServiceCred = credential.schemaType === ECS.SERVICE
        const isExternalIssuer = credential.issuer !== did

        if (isServiceCred && isExternalIssuer) {
          logger.debug('Processing external issuer service credential', { issuer: credential.issuer })
          const resolution = await _resolve(credential.issuer, {
            verifiablePublicRegistries,
            didResolver,
            attrs: credential,
            agentContext,
            skipDigestSRICheck,
          })
          service = resolution.service
          serviceProvider = resolution.serviceProvider
        }
      }
    }),
  )
  service ??= credentials.find((cred): cred is IService => cred.schemaType === ECS.SERVICE)
  serviceProvider ??= credentials.find(
    (cred): cred is IOrg | IPersona => cred.schemaType === ECS.ORG || cred.schemaType === ECS.PERSONA,
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
  logger: IVerreLogger,
  skipDigestSRICheck?: boolean,
  cached = false,
): Promise<{ credential: ICredential; outcome: TrustResolutionOutcome }> {
  logger.debug('Verifying credential', { cached })

  const w3cCredential = getCredential(vp)
  let isVerified: { result: boolean; error?: string }
  if (cached) {
    logger.debug('Using cached credential verification')
    isVerified = { result: true }
  } else isVerified = await verifySignature(vp as W3cJsonLdVerifiablePresentation, agentContext, logger)
  if (!isVerified.result) {
    throw new TrustError(
      TrustErrorCode.INVALID,
      'The verifiable credential proof is not valid with: ' + isVerified.error,
    )
  }

  logger.debug('Credential verified successfully')
  return await processCredential(w3cCredential, verifiablePublicRegistries, skipDigestSRICheck, logger)
}

/**
 * Finds a valid Verifiable Credential inside a Verifiable Presentation.
 * @param vp - The Verifiable Presentation to search.
 * @returns The first valid Verifiable Credential.
 * @throws Error if no valid credential is found.
 */
function getCredential(vp: W3cPresentation): W3cVerifiableCredential {
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
 * @param issuer - Optional issuer DID to validate permissions against the trust registry.
 * @param attrs - Optional attributes to validate against the credential subject schema.
 * @returns A Promise resolving to the processed and validated credential.
 * @throws {TrustError} If validation fails due to missing fields, unsupported types, schema mismatch, or integrity check failure.
 */
async function processCredential(
  w3cCredential: W3cVerifiableCredential,
  verifiablePublicRegistries: VerifiablePublicRegistry[],
  skipDigestSRICheck: boolean = false,
  logger: IVerreLogger,
  issuer?: string,
  attrs?: Record<string, string>,
): Promise<{ credential: ICredential; outcome: TrustResolutionOutcome }> {
  logger.debug('Processing credential', { id: w3cCredential.id })

  const { schema, subject } = resolveSchemaAndSubject(w3cCredential, logger)
  const id = w3cCredential.id as string

  if (schema.type === 'JsonSchemaCredential') {
    logger.debug('Processing JsonSchemaCredential Processing, fetching it', { schemaId: schema.id })
    const jsonSchemaCredential = await fetchJson<W3cVerifiableCredential>(schema.id)
    return processCredential(
      jsonSchemaCredential,
      verifiablePublicRegistries,
      skipDigestSRICheck,
      logger,
      w3cCredential.issuer as string,
      subject as Record<string, string>,
    )
  }

  if (schema.type === 'JsonSchema') {
    logger.debug('Processing JsonSchema credential')
    const { digestSRI: schemaDigestSRI } = schema as Record<string, any>
    const { digestSRI: subjectDigestSRI } = subject as Record<string, any>
    try {
      // Fetch and verify the credential schema integrity
      logger.debug('Fetching credential schema', { schemaId: schema.id })
      const schemaRawText = await fetchText(schema.id)
      const schemaData = JSON.parse(schemaRawText)

      if (!skipDigestSRICheck) {
        verifyDigestSRI(schemaRawText, schemaDigestSRI, logger)
      }

      // Validate the credential against the schema
      validateSchemaContent(schemaData, w3cCredential)

      // Extract the reference URL from the subject if it contains a JSON Schema reference
      const refUrl = getRefUrl(subject)
      const { trustRegistry, schemaId, outcome, schemaUrl } = resolveTrustRegistry(
        refUrl,
        verifiablePublicRegistries,
      )
      logger.debug('Trust registry resolved', { trustRegistry, schemaId, outcome })

      // If a reference URL exists, fetch the referenced schema
      logger.debug('Fetching subject schema')
      const subjectSchemaRawText = await fetchText(schemaUrl)
      const subjectSchema = JSON.parse(subjectSchemaRawText)

      // Verify the integrity of the referenced subject schema using its SRI digest
      if (!skipDigestSRICheck) {
        verifyDigestSRI(subjectSchemaRawText, subjectDigestSRI, logger)
      }

      // Verify the issuer permission over the schema
      await verifyPermission(trustRegistry, schemaId, w3cCredential.issuanceDate, logger, issuer)

      // Validate the credential subject attributes against the JSON schema content
      validateSchemaContent(subjectSchema, attrs)
      const credential = { schemaType: identifySchema(attrs), id, issuer, ...attrs } as ICredential
      return { credential, outcome }
    } catch (error) {
      logger.error('Failed to process credential', error)
      throw new TrustError(TrustErrorCode.INVALID, `Failed to validate credential: ${error.message}`)
    }
  }
  logger.error('Unsupported schema type', { schemaType: schema.type })
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
function resolveSchemaAndSubject(credential: W3cVerifiableCredential, logger: IVerreLogger) {
  logger.debug('Resolving schema and subject from credential')

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

  logger.debug('Schema and subject extracted', { schemaType: schema?.type, hasSubject: !!subject })
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

/**
 * Verifies that the issuer holds a valid ISSUER permission for the specified schema
 * and ensures the credential’s issuance date is not earlier than the permission creation date.
 */
async function verifyPermission(
  trustRegistry: string,
  schemaId: string,
  issuanceDate: string,
  logger: IVerreLogger,
  issuer?: string,
) {
  logger.debug('Verifying issuer permission', { schemaId, issuer })

  if (!issuer) {
    logger.error('Issuer not found for permission verification')
    throw new TrustError(TrustErrorCode.NOT_FOUND, 'Issuer not found')
  }

  const permUrl = `${toIndexerUrl(trustRegistry)}/perm/v1/list?did=${encodeURIComponent(
    issuer,
  )}&type=ISSUER&response_max_size=1&schema_id=${schemaId}`

  logger.debug('Fetching issuer permissions', { permUrl: trustRegistry, schemaId })
  const permResponse = await fetchJson<PermissionResponse>(permUrl)
  const perm = permResponse.permissions?.[0]
  if (!perm || perm.type !== 'ISSUER')
    throw new TrustError(
      TrustErrorCode.INVALID_ISSUER,
      `No valid issuer permissions were found for ${issuer} for schema ${schemaId}`,
    )

  logger.debug('Issuer permission found, verifying dates', { issuer, created: perm.created })
  const issuanceTs = Date.parse(issuanceDate)
  const createdTs = Date.parse(perm.created)
  if (issuanceTs < createdTs) {
    throw new TrustError(
      TrustErrorCode.INVALID_ISSUER,
      'Credential issuance date is earlier than the permission creation date',
    )
  }

  logger.debug('Issuer permission verified successfully', { issuer, schemaId })
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
