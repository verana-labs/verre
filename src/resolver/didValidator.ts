import type {
  W3cVerifiableCredential,
  W3cPresentation,
  W3cJsonLdVerifiablePresentation,
  W3cCredentialSubject,
} from '@credo-ts/core'

import { DIDDocument, Resolver, Service } from 'did-resolver'

import { resolverInstance } from '../libraries/index.js'
import {
  ECS,
  EcsEcosystem,
  IRegistryAdapter,
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
  Participant,
  ParticipantListResponse,
  ParticipantState,
  CredentialResolution,
  VerifyParticipantOptions,
  ParticipantRole,
  LogLevel,
  IVerreLogger,
  FailedCredential,
  CREDENTIAL_FORMAT_LDP_VC,
} from '../types.js'
import {
  fetchJson,
  fetchText,
  handleTrustError,
  identifySchema,
  TrustError,
  validateSchemaContent,
  verifyDigestSRI,
  verifySignature,
  VerreLogger,
} from '../utils/index.js'

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
 * @param options.cache (optional): Cache for trust resolution results. When provided, a successful resolution is stored keyed by DID and returned directly on subsequent calls. Any object implementing the `TrustResolutionCache` interface is accepted, the library provides `InMemoryCache` as a built-in implementation.
 * @param options.skipDigestSRICheck - *(Optional)* When true, skips verification of the credential integrity (digestSRI). Defaults to false.
 * @param options.logger - *(Optional)* Logger instance for the resolution process. Accepts any object that implements the `IVerreLogger` interface.
 * This flag applies **only to credential verification** and its value is determined by the calling service, which is responsible
 * for managing cache validity (e.g. TTL, revocation checks).
 *
 * @returns A promise that resolves to a `TrustResolution` object containing the resolution result,
 * DID document metadata, and trust validation outcome.
 */
// Linked-VP service fragments a trust resolver considers. [VT-CRED-W3C-LINKED-VP] mandates
// #vpr-schemas-*-vtc-vp; the -c-vp forms are kept for backward compatibility with older agents.
export const LINKED_VP_FRAGMENT_PATTERNS = [
  /^vpr-schemas-.*-vtc-vp$/,
  /^vpr-schemas.*-c-vp$/,
  /^vpr-ecs.*-c-vp$/,
]

export async function resolveDID(did: string, options: ResolverConfig): Promise<TrustResolution> {
  const internalOptions: InternalResolverConfig = {
    ...options,
    didResolver: options.didResolver ?? resolverInstance,
  }
  return await _resolve(did, internalOptions)
}

/**
 * Verifies whether a given issuer is an authorized Participant for a specific credential
 * according to the trust registries and schema definitions.
 *
 * @param options - Configuration object containing all required data.
 * @param options.did - The DID of the entity to validate.
 * @param options.jsonSchemaCredentialId - URL or identifier for the JSON schema of the credential.
 * @param options.issuanceDate - The date at which the credential was issued.
 * @param options.verifiablePublicRegistries - A list of public trust registries used for validation.
 * @param options.role - The Participant role to verify.
 * @param options.logger - (Optional) Logger used for debugging.
 */
export async function verifyParticipant(options: VerifyParticipantOptions) {
  const logger = options.logger ?? new VerreLogger(LogLevel.NONE)
  try {
    const { did, jsonSchemaCredentialId, issuanceDate, verifiablePublicRegistries, role } = options
    logger.debug('Verifying participant', { role })
    const credential = await fetchJson<W3cVerifiableCredential>(jsonSchemaCredentialId)
    const { subject } = resolveSchemaAndSubject(credential, logger)
    const { api, schemaId, adapter } = resolveSchemaRef(getRefUrl(subject), verifiablePublicRegistries)
    await verifyAuthorization(api, schemaId, issuanceDate, did, role, logger, adapter)
    logger.debug('Participant verified successfully')
    return { verified: true }
  } catch (error) {
    logger.error('Participant verification failed', error)
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
    const { verifiablePublicRegistries, skipDigestSRICheck, ecsEcosystems } = options
    const { credential: w3cCredential, outcome } = await processCredential(
      credential,
      verifiablePublicRegistries ?? [],
      skipDigestSRICheck,
      logger,
      ecsEcosystems,
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
function resolveSchemaRef(
  ref: string,
  verifiablePublicRegistries?: VerifiablePublicRegistry[],
): {
  api: string
  schemaId: number | string
  outcome: TrustResolutionOutcome
  schemaUrl: string
  adapter?: IRegistryAdapter
  vpr?: string
} {
  const parsed = /^(vpr:[^:]+:[^:]+):cs:(\d+)$/.exec(ref)
  if (parsed) {
    const registry = verifiablePublicRegistries?.find(r => r.scheme === parsed[1])
    if (!registry) {
      throw new TrustError(TrustErrorCode.NOT_SUPPORTED, `Unknown verifiable public registry for: ${ref}`)
    }
    const api = registry.api[0]?.replace(/\/$/, '') ?? ''
    const schemaId = Number(parsed[2])
    return {
      api,
      schemaId,
      outcome: registry.production ? TrustResolutionOutcome.VERIFIED : TrustResolutionOutcome.VERIFIED_TEST,
      schemaUrl: `${api}/v4/credential-schema/js/${schemaId}`,
      adapter: registry.adapter,
      vpr: registry.scheme,
    }
  }

  // self-issued schemas are served by the VS itself and belong to no VPR
  const urlObj = new URL(ref)
  return {
    api: urlObj.origin,
    schemaId: urlObj.pathname.split('/').filter(Boolean).at(-1)!,
    outcome: TrustResolutionOutcome.NOT_TRUSTED,
    schemaUrl: ref,
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
// a resolution made under an allowlist must not be served to a caller using a different one
function cacheKeyFor(did: string, ecsEcosystems?: EcsEcosystem[]): string {
  if (!ecsEcosystems) return did
  const allowlist = ecsEcosystems
    .map(e => `${e.vpr}|${e.did}`)
    .sort()
    .join(',')
  return `${did}#ecs:${allowlist}`
}

async function _resolve(did: string, options: InternalResolverConfig): Promise<TrustResolution> {
  const cacheKey = cacheKeyFor(did, options.ecsEcosystems)
  const cached = options.cache?.get(cacheKey)
  const cachedValue = cached ? await cached : undefined
  if (cachedValue?.verified === true) return cached as Promise<TrustResolution>

  try {
    const didDocument = await retrieveDidDocument(did, options.didResolver)

    try {
      const result = await processDidDocument(did, didDocument, options)
      options.cache?.set(cacheKey, Promise.resolve(result))
      return result
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
 * @param {TrustResolutionCache} cache - Optional provides cache instance for trust resolution results.
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
  const { verifiablePublicRegistries, didResolver, attrs, skipDigestSRICheck, ecsEcosystems } = options

  const credentials: ICredential[] = []
  let serviceProvider: ICredential | undefined
  let service: IService | undefined = attrs
  let outcome: TrustResolutionOutcome = TrustResolutionOutcome.NOT_TRUSTED

  logger.debug('Processing DID services', { serviceCount: didDocument.service.length })
  const serviceResults = await Promise.allSettled(
    didDocument.service.map(async didService => {
      const { type, id } = didService
      const matchesPattern = LINKED_VP_FRAGMENT_PATTERNS.some(pattern => pattern.test(id.split('#')[1]))
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
          logger,
          didResolver,
          skipDigestSRICheck,
          ecsEcosystems,
        )
        credentials.push(credential)
        outcome = vpOutcome

        const isServiceCred = credential.schemaType === ECS.SERVICE
        const isExternalIssuer = credential.issuer !== did

        if (isServiceCred && isExternalIssuer) {
          logger.debug('Processing external issuer service credential', { issuer: credential.issuer })
          const resolution = await _resolve(credential.issuer, { ...options, attrs: credential })
          service = resolution.service
          serviceProvider = resolution.serviceProvider
        }
      }
    }),
  )

  const reasons = serviceResults.flatMap(result => (result.status === 'rejected' ? [result.reason] : []))
  if (reasons.length > 0) throw aggregateCredentialFailures(reasons)

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
 * @returns A valid Verifiable Credential.
 * @throws Error if no valid credential is found.
 */
async function getVerifiedCredential(
  vp: W3cPresentation,
  verifiablePublicRegistries: VerifiablePublicRegistry[],
  logger: IVerreLogger,
  didResolver: Resolver,
  skipDigestSRICheck?: boolean,
  ecsEcosystems?: EcsEcosystem[],
): Promise<{ credential: ICredential; outcome: TrustResolutionOutcome }> {
  logger.debug('Verifying credential', { vp })

  const w3cCredential = getCredential(vp)
  const isVerified = await verifySignature(vp as W3cJsonLdVerifiablePresentation, didResolver, logger)
  if (!isVerified.result) {
    const message = 'The verifiable credential proof is not valid with: ' + isVerified.error
    throw new TrustError(
      TrustErrorCode.INVALID,
      message,
      isVerified.failedCredentials ?? [
        {
          id: typeof w3cCredential?.id === 'string' ? w3cCredential.id : undefined,
          format: CREDENTIAL_FORMAT_LDP_VC,
          error: isVerified.error ?? message,
          errorCode: TrustErrorCode.INVALID,
        },
      ],
    )
  }

  logger.debug('Credential verified successfully')
  try {
    return await processCredential(
      w3cCredential,
      verifiablePublicRegistries,
      skipDigestSRICheck,
      logger,
      ecsEcosystems,
    )
  } catch (error) {
    throw toCredentialFailure(error, w3cCredential)
  }
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
 * @param issuer - Optional issuer DID to validate as a Participant against the registry.
 * @param attrs - Optional attributes to validate against the credential subject schema.
 * @param sourceCredential - Optional credential the validation started from. When a credential
 * declares a `JsonSchemaCredential`, this function recurses on the *schema* credential, so the
 * credential originally presented has to be carried down to source the validity window and the
 * raw credential exposed to consumers.
 * @returns A Promise resolving to the processed and validated credential.
 * @throws {TrustError} If validation fails due to missing fields, unsupported types, schema mismatch, or integrity check failure.
 */
async function processCredential(
  w3cCredential: W3cVerifiableCredential,
  verifiablePublicRegistries: VerifiablePublicRegistry[],
  skipDigestSRICheck: boolean = false,
  logger: IVerreLogger,
  ecsEcosystems?: EcsEcosystem[],
  issuer?: string,
  issuanceDate?: string,
  attrs?: Record<string, string>,
  sourceCredential?: W3cVerifiableCredential,
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
      ecsEcosystems,
      w3cCredential.issuer as string,
      w3cCredential.issuanceDate as string,
      subject as Record<string, string>,
      sourceCredential ?? w3cCredential,
    )
  }

  if (schema.type === 'JsonSchema') {
    logger.debug('Processing JsonSchema credential')
    const { digestSRI: schemaDigestSRI } = schema as Record<string, any>
    const { digestSRI: subjectDigestSRI } = subject as Record<string, any>
    try {
      // Extract the reference URL from the subject if it contains a JSON Schema reference
      const refUrl = getRefUrl(subject)
      const { api, schemaId, outcome, schemaUrl, adapter, vpr } = resolveSchemaRef(
        refUrl,
        verifiablePublicRegistries,
      )
      logger.debug('Schema reference resolved', { api, schemaId, outcome, hasAdapter: !!adapter })

      if (!issuer || !issuanceDate)
        throw new TrustError(
          TrustErrorCode.NOT_AUTHORIZED,
          `Missing required fields: ${!issuer ? 'issuer' : 'issuanceDate'}`,
        )

      // Schema fetches and participant check share no dependencies — run in parallel
      logger.debug('Fetching schemas and verifying participant in parallel')
      const [schemaRawText, subjectSchemaRawText] = await Promise.all([
        fetchText(schema.id),
        adapter ? adapter.fetchSchema(schemaUrl) : fetchText(schemaUrl),
        verifyAuthorization(api, schemaId, issuanceDate, issuer, ParticipantRole.ISSUER, logger, adapter),
      ])

      const schemaData = JSON.parse(schemaRawText)
      const subjectSchema = JSON.parse(subjectSchemaRawText)

      if (!skipDigestSRICheck) {
        verifyDigestSRI(schemaRawText, schemaDigestSRI, logger)
        verifyDigestSRI(subjectSchemaRawText, subjectDigestSRI, logger)
      }

      validateSchemaContent(schemaData, w3cCredential)

      // Validate the credential subject attributes against the JSON schema content
      validateSchemaContent(subjectSchema, attrs)
      const schemaType = await identifySchema(
        subjectSchema,
        ecsEcosystems ? { ecsEcosystems, schemaId, vprId: vpr, adapter, logger } : undefined,
      )
      const source = sourceCredential ?? w3cCredential
      const credential = {
        schemaType,
        id,
        issuer,
        ...attrs,
        ...normalizeValidityWindow(source),
        raw: source,
      } as ICredential
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
 * Normalises a credential's validity window across credential data model versions.
 *
 * VCDM 2.0 uses `validFrom` / `validUntil`; VCDM 1.1 uses `issuanceDate` / `expirationDate`.
 * Normalising here means consumers never have to branch on the credential version.
 *
 * Absent bounds are omitted rather than set to `undefined`, so a credential without an
 * expiry simply has no `validUntil`.
 *
 * @param credential - The credential to read the window from.
 * @returns The normalised `validFrom` / `validUntil` pair.
 */
function normalizeValidityWindow(credential: W3cVerifiableCredential): {
  validFrom?: string
  validUntil?: string
} {
  const vc = credential as unknown as Record<string, unknown>
  const validFrom = (vc.validFrom ?? vc.issuanceDate) as string | undefined
  const validUntil = (vc.validUntil ?? vc.expirationDate) as string | undefined

  return {
    ...(validFrom ? { validFrom } : {}),
    ...(validUntil ? { validUntil } : {}),
  }
}

/**
 * Attaches per-credential failure detail to an error raised while validating a specific credential.
 *
 * Errors that already carry `failedCredentials` (e.g. signature failures identified per
 * embedded VC) are passed through untouched, so the more precise attribution wins.
 *
 * @param error - The error raised while validating the credential.
 * @param credential - The credential being validated when the error was raised.
 * @returns A `TrustError` carrying the failure detail for this credential.
 */
function toCredentialFailure(error: unknown, credential: W3cVerifiableCredential): TrustError {
  if (error instanceof TrustError && error.failedCredentials) return error

  const message = error instanceof Error ? error.message : String(error)
  const errorCode =
    error instanceof TrustError
      ? (error.metadata.errorCode ?? TrustErrorCode.INVALID)
      : TrustErrorCode.INVALID

  return new TrustError(errorCode, message, [
    {
      id: typeof credential?.id === 'string' ? credential.id : undefined,
      format: CREDENTIAL_FORMAT_LDP_VC,
      error: message,
      errorCode,
    },
  ])
}

/**
 * Combines failures raised across the DID document's services into a single error.
 *
 * The first failure supplies the top-level message and code (preserving the message a
 * caller would previously have seen), while every failure contributes its per-credential
 * detail so none is lost.
 *
 * @param reasons - The rejection reasons collected from the service resolutions.
 * @returns A `TrustError` carrying the combined per-credential detail.
 */
function aggregateCredentialFailures(reasons: unknown[]): TrustError {
  const failedCredentials = reasons.flatMap<FailedCredential>(reason =>
    reason instanceof TrustError ? (reason.failedCredentials ?? []) : [],
  )
  const [first] = reasons
  if (first instanceof TrustError) {
    return new TrustError(
      first.metadata.errorCode ?? TrustErrorCode.INVALID,
      first.message,
      failedCredentials,
    )
  }
  return new TrustError(
    TrustErrorCode.INVALID,
    first instanceof Error ? first.message : String(first),
    failedCredentials,
  )
}

/**
 * Verifies that an entity is an authorized Participant for the specified schema
 * and ensures the credential's issuance date is not earlier than the Participant creation date.
 */
async function verifyAuthorization(
  api: string,
  schemaId: number | string,
  issuanceDate: string,
  did: string,
  role: ParticipantRole,
  logger: IVerreLogger,
  adapter?: IRegistryAdapter,
) {
  logger.debug('Verifying participant', { schemaId, did, hasAdapter: !!adapter })

  let participants: Pick<
    Participant,
    'role' | 'created' | 'effective_from' | 'effective_until' | 'participant_state'
  >[]

  if (adapter) {
    logger.debug('Using registry adapter for participant check', { schemaId, did })
    const found = await adapter.fetchParticipant(schemaId, did, role, issuanceDate)
    participants = found ? [found] : []
  } else {
    // `when` narrows to entries effective at issuance, so a later grant cannot shadow the one that covered it
    const participantUrl = `${api}/v4/participant/list?did=${encodeURIComponent(
      did,
    )}&role=${role}&schema_id=${schemaId}&when=${encodeURIComponent(issuanceDate)}`
    logger.debug('Fetching participants', { participantUrl, schemaId })
    const response = await fetchJson<ParticipantListResponse>(participantUrl)
    participants = response.participants ?? []
  }

  const issuanceTs = Date.parse(issuanceDate)
  const authorized = participants.find(participant => {
    if (participant.role !== role) return false
    const effectiveFrom = Date.parse(participant.effective_from ?? participant.created)
    const effectiveUntil = participant.effective_until ? Date.parse(participant.effective_until) : Date.now()
    return issuanceTs >= effectiveFrom && issuanceTs <= effectiveUntil
  })

  if (!authorized)
    throw new TrustError(
      TrustErrorCode.NOT_AUTHORIZED,
      `No ${role} Participant effective at ${issuanceDate} was found for the specified DID: ${did} for schema ${schemaId}`,
    )

  // later expiry does not invalidate an already-issued credential, every other state does:
  // REPAID reports a slash that may also mask a revocation, FUTURE and INACTIVE were never effective
  if (
    authorized.participant_state !== ParticipantState.ACTIVE &&
    authorized.participant_state !== ParticipantState.EXPIRED
  )
    throw new TrustError(
      TrustErrorCode.NOT_AUTHORIZED,
      `Participant for the specified DID: ${did} for schema ${schemaId} is ${authorized.participant_state ?? 'in an unknown state'}`,
    )

  logger.debug('Participant verified successfully', { did, schemaId })
}
