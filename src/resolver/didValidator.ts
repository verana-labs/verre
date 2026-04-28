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
  PermissionResponse,
  CredentialResolution,
  VerifyPermissionsOptions,
  PermissionType,
  LogLevel,
  IVerreLogger,
  PresentationType,
  VpOutcome,
  VpOutcomeWithError,
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
 * Linked Verifiable Presentation fragment patterns.
 *
 * The fragment portion of a `LinkedVerifiablePresentation` service id encodes
 * both its target schema family (`vpr-schemas` or `vpr-ecs`) and its
 * presentation type (Verifiable Trust Credential vs. Verifiable Trust JSON
 * Schema Credential).
 *
 * Verre supports both the legacy spec v3 suffixes (`-c-vp`, `-jsc-vp`) and
 * the spec v4 suffixes (`-vtc-vp`, `-vtjsc-vp`) so that DID Documents
 * conforming to either version remain resolvable. New deployments should
 * emit v4 suffixes.
 */
const LINKED_VP_FRAGMENT_PATTERNS: { regex: RegExp; type: PresentationType; legacy: boolean }[] = [
  // Verifiable Trust Credential
  { regex: /^vpr-(schemas|ecs).*-c-vp$/, type: PresentationType.VTC, legacy: true },
  { regex: /^vpr-(schemas|ecs).*-vtc-vp$/, type: PresentationType.VTC, legacy: false },
  // Verifiable Trust JSON Schema Credential
  { regex: /^vpr-(schemas|ecs).*-jsc-vp$/, type: PresentationType.VTJSC, legacy: true },
  { regex: /^vpr-(schemas|ecs).*-vtjsc-vp$/, type: PresentationType.VTJSC, legacy: false },
]

/**
 * Classify the fragment of a DID service id as a known linked-vp variant.
 *
 * @param serviceId - The full service id (`<did>#<fragment>`).
 * @returns The presentation type when the fragment matches a known pattern,
 *          otherwise `null`.
 */
function classifyVpFragment(serviceId: string): { presentationType: PresentationType } | null {
  const fragment = serviceId.split('#')[1]
  if (!fragment) return null
  for (const { regex, type } of LINKED_VP_FRAGMENT_PATTERNS) {
    if (regex.test(fragment)) return { presentationType: type }
  }
  return null
}

/**
 * Heuristic check for service ids that *appear* to be linked-vp entries
 * but use an unrecognised fragment suffix. Used to decide whether to emit
 * `FRAGMENT_NOT_CONFORMANT` (recognisably-bad) versus silently skipping
 * unrelated services (e.g. `did-communication`).
 */
function looksLikeLinkedVpFragment(serviceId: string): boolean {
  const fragment = serviceId.split('#')[1]
  return Boolean(fragment && /^vpr-(schemas|ecs)/.test(fragment))
}

/**
 * Where in the resolution pipeline a coarse `TrustError` was raised.
 * Used by `mapToFineGrainedCode` to translate legacy codes emitted by
 * existing throw sites into the new fine-grained codes that populate
 * `TrustResolution.invalidPresentations`.
 */
type ErrorContext =
  | 'fragment'
  | 'vp-fetch'
  | 'vp-format'
  | 'vp-signature'
  | 'cred-format'
  | 'cred-schema-ref'
  | 'cred-schema-fetch'
  | 'cred-schema-validate'
  | 'cred-digest'
  | 'cred-permission'
  | 'cred-whitelist'
  | 'cred-registry'
  | 'cred-other'

/**
 * Translate a coarse `TrustErrorCode` thrown from a legacy code path into
 * the fine-grained code appropriate for the calling context.
 *
 * Existing throw sites continue to use the legacy codes so that the public
 * `metadata.errorCode` and `handleTrustError` behaviour is unchanged.
 * The fine-grained codes are surfaced only on the new
 * `invalidPresentations` array, which downstream consumers (such as the
 * verana-resolver) can opt into.
 */
function mapToFineGrainedCode(coarse: TrustErrorCode, context: ErrorContext): TrustErrorCode {
  // Codes already specific are returned as-is so that explicit throws of
  // fine-grained codes (e.g. ECS_TRUST_REGISTRY_NOT_WHITELISTED) survive
  // unchanged.
  switch (coarse) {
    case TrustErrorCode.ECS_TRUST_REGISTRY_NOT_WHITELISTED:
    case TrustErrorCode.REGISTRY_NOT_CONFIGURED:
    case TrustErrorCode.FRAGMENT_NOT_CONFORMANT:
    case TrustErrorCode.DEREFERENCE_FAILED:
    case TrustErrorCode.VP_INVALID_FORMAT:
    case TrustErrorCode.VP_SIGNATURE_INVALID:
    case TrustErrorCode.VP_HOLDER_MISMATCH:
    case TrustErrorCode.VP_NO_CREDENTIALS:
    case TrustErrorCode.CREDENTIAL_SIGNATURE_INVALID:
    case TrustErrorCode.CREDENTIAL_INVALID_FORMAT:
    case TrustErrorCode.SCHEMA_NOT_FOUND:
    case TrustErrorCode.CREDENTIAL_SCHEMA_MISMATCH:
    case TrustErrorCode.SCHEMA_DIGEST_MISMATCH:
    case TrustErrorCode.ISSUER_PERMISSION_MISSING:
    case TrustErrorCode.ISSUER_PERMISSION_NOT_EFFECTIVE:
      return coarse
  }

  switch (context) {
    case 'fragment':
      return TrustErrorCode.FRAGMENT_NOT_CONFORMANT
    case 'vp-fetch':
      return TrustErrorCode.DEREFERENCE_FAILED
    case 'vp-format':
      // NOT_FOUND from `getCredentials` (no creds) vs INVALID (bad VC type)
      return coarse === TrustErrorCode.NOT_FOUND
        ? TrustErrorCode.VP_NO_CREDENTIALS
        : TrustErrorCode.VP_INVALID_FORMAT
    case 'vp-signature':
      return TrustErrorCode.VP_SIGNATURE_INVALID
    case 'cred-format':
      return TrustErrorCode.CREDENTIAL_INVALID_FORMAT
    case 'cred-schema-ref':
      return TrustErrorCode.CREDENTIAL_INVALID_FORMAT
    case 'cred-schema-fetch':
      return TrustErrorCode.SCHEMA_NOT_FOUND
    case 'cred-schema-validate':
      return TrustErrorCode.CREDENTIAL_SCHEMA_MISMATCH
    case 'cred-digest':
      return TrustErrorCode.SCHEMA_DIGEST_MISMATCH
    case 'cred-permission':
      // INVALID_PERMISSIONS may carry either MISSING or NOT_EFFECTIVE; use
      // message heuristics to disambiguate (kept pragmatic since the legacy
      // throw uses the same code for both subcases).
      return TrustErrorCode.ISSUER_PERMISSION_MISSING
    case 'cred-whitelist':
      return TrustErrorCode.ECS_TRUST_REGISTRY_NOT_WHITELISTED
    case 'cred-registry':
      return TrustErrorCode.REGISTRY_NOT_CONFIGURED
    case 'cred-other':
    default:
      return coarse
  }
}

/**
 * Refine a fine-grained code based on the inner error message. Keeps the
 * mapping conservative: only used when the coarse code is `INVALID_PERMISSIONS`
 * and we can distinguish "no permission" from "issuance out of range".
 */
function refinePermissionCode(message: string | undefined): TrustErrorCode {
  if (!message) return TrustErrorCode.ISSUER_PERMISSION_MISSING
  return /effective range|effective_from|effective_until|issuance date/i.test(message)
    ? TrustErrorCode.ISSUER_PERMISSION_NOT_EFFECTIVE
    : TrustErrorCode.ISSUER_PERMISSION_MISSING
}

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
export async function resolveDID(did: string, options: ResolverConfig): Promise<TrustResolution> {
  const internalOptions: InternalResolverConfig = {
    ...options,
    didResolver: options.didResolver ?? resolverInstance,
  }
  return await _resolve(did, internalOptions)
}

/**
 * Verifies whether a given issuer has permission to issue a specific credential
 * according to the trust registries and schema definitions.
 *
 * @param options - Configuration object containing all required data.
 * @param options.did - The DID of the entity to validate.
 * @param options.jsonSchemaCredentialId - URL or identifier for the JSON schema of the credential.
 * @param options.issuanceDate - The date at which the credential was issued.
 * @param options.verifiablePublicRegistries - A list of public trust registries used for validation.
 * @param options.permissionType - The type of permission to verify.
 * @param options.logger - (Optional) Logger used for debugging.
 */
export async function verifyPermissions(options: VerifyPermissionsOptions) {
  const logger = options.logger ?? new VerreLogger(LogLevel.NONE)
  try {
    const { did, jsonSchemaCredentialId, issuanceDate, verifiablePublicRegistries, permissionType } = options
    logger.debug('Verifying permissions', { permissionType })
    const credential = await fetchJson<W3cVerifiableCredential>(jsonSchemaCredentialId)
    const { subject } = resolveSchemaAndSubject(credential, logger)
    const { trustRegistry, schemaId, adapter } = resolveTrustRegistry(
      getRefUrl(subject),
      verifiablePublicRegistries,
    )
    await verifyPermission(trustRegistry, schemaId, issuanceDate, did, permissionType, logger, adapter)
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
): {
  trustRegistry: string
  schemaId: string
  outcome: TrustResolutionOutcome
  schemaUrl: string
  adapter?: IRegistryAdapter
  /**
   * The matched registry entry, or `undefined` if `refUrl` does not start with
   * any configured registry id. Exposed so that callers can apply
   * registry-scoped policies (e.g. `allowedEcsEcosystems`) without re-running
   * the prefix match.
   */
  registry?: VerifiablePublicRegistry
} {
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
    adapter: registry?.adapter,
    registry,
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
  const cached = options.cache?.get(did)
  if (cached && (await cached).verified === true) return cached as Promise<TrustResolution>

  try {
    const didDocument = await retrieveDidDocument(did, options.didResolver)

    try {
      const result = await processDidDocument(did, didDocument, options)
      options.cache?.set(did, Promise.resolve(result))
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
  const { verifiablePublicRegistries, didResolver, attrs, skipDigestSRICheck } = options

  const credentials: ICredential[] = []
  const validPresentations: VpOutcome[] = []
  const invalidPresentations: VpOutcomeWithError[] = []
  let serviceProvider: ICredential | undefined
  let service: IService | undefined = attrs
  let outcome: TrustResolutionOutcome = TrustResolutionOutcome.NOT_TRUSTED

  logger.debug('Processing DID services', { serviceCount: didDocument.service.length })

  // Process every linked-vp service entry independently. We use
  // `Promise.allSettled` so that a failure in any single VP does not
  // abort processing of its siblings — this is what enables the
  // per-VP `validPresentations` / `invalidPresentations` accumulator
  // pattern. Per-VP outcomes (and any per-credential outcomes inside a
  // VP) are pushed to the appropriate array and an aggregate outcome is
  // tracked for the legacy `outcome` field (best of all valid VPs).
  await Promise.allSettled(
    didDocument.service.map(async didService => {
      const { type, id } = didService
      // Only LinkedVerifiablePresentation entries are in scope.
      if (type !== 'LinkedVerifiablePresentation') {
        logger.debug('Skipping non-linked-vp service', { id, type })
        return
      }

      const classification = classifyVpFragment(id)
      if (!classification) {
        // Emit FRAGMENT_NOT_CONFORMANT only when the fragment looks like a
        // linked-vp entry (starts with `vpr-schemas` or `vpr-ecs`); silently
        // skip unrelated linked-vp services that happen to point elsewhere.
        if (looksLikeLinkedVpFragment(id)) {
          invalidPresentations.push({
            serviceId: id,
            vpUrl: id,
            credentialIds: [],
            errorCode: TrustErrorCode.FRAGMENT_NOT_CONFORMANT,
            errorMessage: `Linked-vp fragment '${id.split('#')[1]}' does not match any known suffix (-c-vp / -vtc-vp / -jsc-vp / -vtjsc-vp)`,
          })
        }
        return
      }

      const presentationType = classification.presentationType
      logger.debug('Evaluating DID service', { id, type, presentationType })

      const ctx = {
        did,
        serviceId: id,
        presentationType,
        verifiablePublicRegistries: verifiablePublicRegistries ?? [],
        didResolver,
        skipDigestSRICheck,
        logger,
        cache: options.cache,
      }

      const vpResult = await processLinkedVp(didService, ctx)

      // Per-VP outcome bookkeeping.
      if (vpResult.kind === 'vp-failed') {
        invalidPresentations.push({
          serviceId: id,
          vpUrl: vpResult.vpUrl ?? id,
          presentationType,
          credentialIds: [],
          errorCode: vpResult.errorCode,
          errorMessage: vpResult.errorMessage,
        })
        return
      }

      // Per-credential outcome bookkeeping. A multi-credential VP may
      // appear in BOTH arrays — its passing credentials in
      // `validPresentations`, its failing credentials in
      // `invalidPresentations` (grouped by error code).
      if (vpResult.validCredentials.length > 0) {
        validPresentations.push({
          serviceId: id,
          vpUrl: vpResult.vpUrl,
          presentationType,
          credentialIds: vpResult.validCredentials.map(c => c.credentialId),
        })

        for (const valid of vpResult.validCredentials) {
          credentials.push(valid.credential)
          if (valid.outcome > outcome) outcome = valid.outcome // upgrade best outcome
        }
      }

      // Group failing credentials by error code so consumers can see
      // exactly which credentials broke each rule.
      const failuresByCode = new Map<TrustErrorCode, { ids: string[]; message: string }>()
      for (const failed of vpResult.invalidCredentials) {
        const slot = failuresByCode.get(failed.errorCode)
        if (slot) {
          slot.ids.push(failed.credentialId)
        } else {
          failuresByCode.set(failed.errorCode, {
            ids: [failed.credentialId],
            message: failed.errorMessage,
          })
        }
      }
      for (const [code, { ids, message }] of failuresByCode.entries()) {
        invalidPresentations.push({
          serviceId: id,
          vpUrl: vpResult.vpUrl,
          presentationType,
          credentialIds: ids,
          errorCode: code,
          errorMessage: message,
        })
      }

      // Indirect resolution: when the SERVICE credential is issued by a
      // DID different from the one being resolved, recurse into the
      // issuer's DID Document so that its `serviceProvider` (org/persona)
      // attaches to the current trust resolution. Same semantics as the
      // legacy implementation, only invoked once per VP from the first
      // valid SERVICE credential found.
      const externalServiceCred = vpResult.validCredentials.find(
        (c): c is { credentialId: string; credential: IService; outcome: TrustResolutionOutcome } =>
          c.credential.schemaType === ECS.SERVICE && c.credential.issuer !== did,
      )?.credential
      if (externalServiceCred) {
        logger.debug('Processing external issuer service credential', {
          issuer: externalServiceCred.issuer,
        })
        const resolution = await _resolve(externalServiceCred.issuer, {
          verifiablePublicRegistries,
          didResolver,
          attrs: externalServiceCred,
          skipDigestSRICheck,
          cache: options.cache,
        })
        service = resolution.service
        serviceProvider = resolution.serviceProvider
      }
    }),
  )

  service ??= credentials.find((cred): cred is IService => cred.schemaType === ECS.SERVICE)
  serviceProvider ??= credentials.find(
    (cred): cred is IOrg | IPersona => cred.schemaType === ECS.ORG || cred.schemaType === ECS.PERSONA,
  )

  // If proof of trust exists, return the verified result. The legacy
  // top-level fields (`service`, `serviceProvider`, `outcome`,
  // `verified`) are preserved unchanged so existing consumers continue
  // to work; the new `validPresentations` / `invalidPresentations`
  // arrays are exposed alongside.
  if (serviceProvider && service) {
    return {
      didDocument,
      outcome,
      verified: true,
      service,
      serviceProvider,
      validPresentations,
      invalidPresentations,
    }
  }
  // No verified service/serviceProvider was assembled. Distinguish two
  // shapes of failure for the coarse top-level code consumers see on
  // `metadata.errorCode`:
  //
  //   * `INVALID`   — at least one VP was attempted and failed validation
  //                   (signature, schema, permission, etc.). Legacy
  //                   behaviour: a credential we tried to verify was
  //                   rejected, so the overall outcome is "invalid". This
  //                   matches the integration test which mocks a VP with
  //                   a broken JWS and expects `INVALID` at the top level.
  //   * `NOT_FOUND` — nothing valid AND nothing was even tried (e.g. all
  //                   linked-vp fragments were classified as unrelated /
  //                   skipped, or there were no recognisable VPs at all).
  //
  // The fine-grained per-VP details remain on `invalidPresentations`
  // regardless, so callers that opt into them keep full diagnostics.
  const triedSomething = invalidPresentations.length > 0
  const err = new TrustError(
    triedSomething ? TrustErrorCode.INVALID : TrustErrorCode.NOT_FOUND,
    triedSomething
      ? 'No valid service + serviceProvider pair could be assembled; see invalidPresentations for per-VP failures.'
      : 'Valid serviceProvider and service were not found',
  )
  err.validPresentations = validPresentations
  err.invalidPresentations = invalidPresentations
  throw err
}

/** Result of processing a single linked-vp service entry. */
type LinkedVpResult =
  | {
      kind: 'vp-failed'
      vpUrl?: string
      errorCode: TrustErrorCode
      errorMessage: string
    }
  | {
      kind: 'vp-processed'
      vpUrl: string
      validCredentials: { credentialId: string; credential: ICredential; outcome: TrustResolutionOutcome }[]
      invalidCredentials: { credentialId: string; errorCode: TrustErrorCode; errorMessage: string }[]
    }

/** Aggregated context for processing a single linked-vp entry. */
type LinkedVpContext = {
  did: string
  serviceId: string
  presentationType: PresentationType
  verifiablePublicRegistries: VerifiablePublicRegistry[]
  didResolver: Resolver
  skipDigestSRICheck?: boolean
  logger: IVerreLogger
  cache?: InternalResolverConfig['cache']
}

/**
 * Process a single `LinkedVerifiablePresentation` service entry end-to-end:
 * dereference the VP, verify its signature, then validate every credential
 * it contains against the appropriate flow (VTC or VTJSC).
 *
 * Returns a structured result so the caller can update the per-VP /
 * per-credential outcome arrays without losing partial progress.
 */
async function processLinkedVp(didService: Service, ctx: LinkedVpContext): Promise<LinkedVpResult> {
  const { logger, presentationType, verifiablePublicRegistries, didResolver, skipDigestSRICheck } = ctx

  // 1) Dereference the VP.
  let vp: W3cPresentation
  let vpUrl: string
  try {
    vp = await resolveServiceVP(didService)
    const endpoints = Array.isArray(didService.serviceEndpoint)
      ? didService.serviceEndpoint
      : [didService.serviceEndpoint]
    vpUrl = (endpoints[0] as string) ?? ctx.serviceId
  } catch (error) {
    const code = error instanceof TrustError ? error.metadata.errorCode! : TrustErrorCode.INVALID_REQUEST
    return {
      kind: 'vp-failed',
      errorCode: mapToFineGrainedCode(code, 'vp-fetch'),
      errorMessage: error instanceof Error ? error.message : String(error),
    }
  }

  // 2) Verify VP signature (this also recursively verifies each embedded
  // credential's own signature; one bad signature poisons the whole VP).
  const sig = await verifySignature(vp as W3cJsonLdVerifiablePresentation, didResolver, logger)
  if (!sig.result) {
    return {
      kind: 'vp-failed',
      vpUrl,
      errorCode: TrustErrorCode.VP_SIGNATURE_INVALID,
      errorMessage: `Verifiable presentation signature invalid: ${sig.error ?? 'unknown'}`,
    }
  }

  // 3) Extract all credentials from the VP.
  let vcs: W3cVerifiableCredential[]
  try {
    vcs = getCredentials(vp)
  } catch (error) {
    const code = error instanceof TrustError ? error.metadata.errorCode! : TrustErrorCode.INVALID
    return {
      kind: 'vp-failed',
      vpUrl,
      errorCode: mapToFineGrainedCode(code, 'vp-format'),
      errorMessage: error instanceof Error ? error.message : String(error),
    }
  }

  // 4) Validate each credential independently.
  const validCredentials: {
    credentialId: string
    credential: ICredential
    outcome: TrustResolutionOutcome
  }[] = []
  const invalidCredentials: { credentialId: string; errorCode: TrustErrorCode; errorMessage: string }[] = []

  for (const vc of vcs) {
    const credentialId = (vc.id as string) ?? '<no-id>'
    try {
      const { credential, outcome } =
        presentationType === PresentationType.VTJSC
          ? await processVtjscCredential(vc, verifiablePublicRegistries, skipDigestSRICheck, logger)
          : await processCredential(vc, verifiablePublicRegistries, skipDigestSRICheck, logger)
      validCredentials.push({ credentialId, credential, outcome })
    } catch (error) {
      const innerMessage = error instanceof Error ? error.message : String(error)
      let coarse = error instanceof TrustError ? error.metadata.errorCode! : TrustErrorCode.INVALID
      // Refine INVALID_PERMISSIONS into MISSING vs NOT_EFFECTIVE based on
      // the message. This is the only legacy code with an internal split.
      if (coarse === TrustErrorCode.INVALID_PERMISSIONS) {
        coarse = refinePermissionCode(innerMessage)
      }
      const fineGrained = mapToFineGrainedCode(coarse, 'cred-other')
      invalidCredentials.push({
        credentialId,
        errorCode: fineGrained,
        errorMessage: innerMessage,
      })
      logger.debug('Credential validation failed', {
        credentialId,
        coarse,
        fineGrained,
        message: innerMessage,
      })
    }
  }

  return { kind: 'vp-processed', vpUrl, validCredentials, invalidCredentials }
}

/**
 * Validate a Verifiable Trust JSON Schema Credential (VTJSC) presented
 * directly via a `-jsc-vp` / `-vtjsc-vp` linked-vp service.
 *
 * VTJSCs differ from VTCs in two ways:
 *
 * 1. They are themselves credentials of type `JsonSchemaCredential` whose
 *    inner `credentialSchema.type` is `JsonSchema`. There is no outer
 *    "user-data" credential.
 * 2. The relevant trust assertion is **not** an ISSUER permission for a
 *    schema, but rather "the Ecosystem DID controls this schema". The
 *    cryptographic proof comes from the credential signature; the
 *    Ecosystem-vs-registry binding is enforced via the optional
 *    `allowedEcsEcosystems` whitelist on the matched registry.
 *
 * The returned `ICredential` has `id` and `issuer` (the Ecosystem DID)
 * populated and `schemaType` set to the identified ECS variant when
 * applicable, or `'unknown'` for non-ECS schemas.
 */
async function processVtjscCredential(
  w3cCredential: W3cVerifiableCredential,
  verifiablePublicRegistries: VerifiablePublicRegistry[],
  skipDigestSRICheck: boolean = false,
  logger: IVerreLogger,
): Promise<{ credential: ICredential; outcome: TrustResolutionOutcome }> {
  logger.debug('Processing VTJSC credential', { id: w3cCredential.id })

  const { schema, subject } = resolveSchemaAndSubject(w3cCredential, logger)

  // A VTJSC's own schema MUST be `JsonSchema` (i.e. the credential IS the
  // JSC). VTC-like indirection (`JsonSchemaCredential`) is rejected here.
  if (schema.type !== 'JsonSchema') {
    throw new TrustError(
      TrustErrorCode.CREDENTIAL_INVALID_FORMAT,
      `VTJSC must declare credentialSchema.type === 'JsonSchema'; got '${schema.type}'`,
    )
  }

  const refUrl = getRefUrl(subject)
  const { schemaUrl, outcome, adapter, registry } = resolveTrustRegistry(refUrl, verifiablePublicRegistries)

  const { digestSRI: schemaDigestSRI } = schema as Record<string, any>
  const { digestSRI: subjectDigestSRI } = subject as Record<string, any>

  const [schemaRawText, subjectSchemaRawText] = await Promise.all([
    fetchText(schema.id),
    adapter ? adapter.fetchSchema(schemaUrl) : fetchText(schemaUrl),
  ])

  if (!skipDigestSRICheck) {
    verifyDigestSRI(schemaRawText, schemaDigestSRI, logger)
    verifyDigestSRI(subjectSchemaRawText, subjectDigestSRI, logger)
  }

  const schemaData = JSON.parse(schemaRawText)
  const subjectSchema = JSON.parse(subjectSchemaRawText)

  // The VTJSC must validate against its own meta-schema (typically the
  // W3C JsonSchemaCredential schema). No `attrs` validation step here:
  // there is no outer credential carrying user data.
  validateSchemaContent(schemaData, w3cCredential)

  const ecsType = identifySchema(subjectSchema)

  // ECS whitelist enforcement: identical to the VTC path, except that
  // for VTJSCs the JSC issuer is simply `w3cCredential.issuer` (no
  // recursion).
  if (ecsType !== null && registry?.allowedEcsEcosystems && registry.allowedEcsEcosystems.length > 0) {
    const jscIssuer =
      typeof w3cCredential.issuer === 'string'
        ? w3cCredential.issuer
        : (w3cCredential.issuer as { id?: string } | undefined)?.id
    if (!jscIssuer || !registry.allowedEcsEcosystems.includes(jscIssuer)) {
      throw new TrustError(
        TrustErrorCode.ECS_TRUST_REGISTRY_NOT_WHITELISTED,
        `Ecosystem DID ${jscIssuer ?? '<unknown>'} is not whitelisted to issue ${ecsType} schemas in registry ${registry.id}`,
      )
    }
    logger.debug('VTJSC ecosystem whitelist passed', { jscIssuer, ecsType, registryId: registry.id })
  }

  const issuer =
    typeof w3cCredential.issuer === 'string'
      ? w3cCredential.issuer
      : ((w3cCredential.issuer as { id?: string } | undefined)?.id ?? '')

  const credential: ICredential = {
    schemaType: ecsType ?? 'unknown',
    id: (w3cCredential.id as string) ?? '',
    issuer,
  } as ICredential
  return { credential, outcome }
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
 * Returns all Verifiable Credentials inside a Verifiable Presentation.
 *
 * Unlike the original `getCredential` (single-result, fail-fast), this
 * iterator returns *every* credential whose `type` array includes
 * `VerifiableCredential`. This enables per-credential validation downstream
 * so a multi-credential VP that is partially valid can be reported
 * accurately (some credentials in `validPresentations`, others in
 * `invalidPresentations`).
 *
 * @param vp - The Verifiable Presentation to inspect.
 * @returns Non-empty array of credentials. Throws if the VP holds none.
 * @throws {TrustError} `NOT_FOUND` when the VP has no credentials at all,
 *                     `INVALID` when none are typed as `VerifiableCredential`.
 */
function getCredentials(vp: W3cPresentation): W3cVerifiableCredential[] {
  if (
    !vp.verifiableCredential ||
    !Array.isArray(vp.verifiableCredential) ||
    vp.verifiableCredential.length === 0
  ) {
    throw new TrustError(TrustErrorCode.NOT_FOUND, 'No verifiable credential found in the response')
  }

  const validCredentials = vp.verifiableCredential.filter(vc =>
    vc.type.includes('VerifiableCredential'),
  ) as W3cVerifiableCredential[]

  if (validCredentials.length === 0) {
    throw new TrustError(TrustErrorCode.INVALID, 'No valid verifiable credential found in the response')
  }

  return validCredentials
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
  issuanceDate?: string,
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
      w3cCredential.issuanceDate as string,
      subject as Record<string, string>,
    )
  }

  if (schema.type === 'JsonSchema') {
    logger.debug('Processing JsonSchema credential')
    const { digestSRI: schemaDigestSRI } = schema as Record<string, any>
    const { digestSRI: subjectDigestSRI } = subject as Record<string, any>
    try {
      // Extract the reference URL from the subject if it contains a JSON Schema reference
      const refUrl = getRefUrl(subject)
      const { trustRegistry, schemaId, outcome, schemaUrl, adapter, registry } = resolveTrustRegistry(
        refUrl,
        verifiablePublicRegistries,
      )
      logger.debug('Trust registry resolved', { trustRegistry, schemaId, outcome, hasAdapter: !!adapter })

      if (!issuer || !issuanceDate)
        throw new TrustError(
          TrustErrorCode.INVALID_PERMISSIONS,
          `Missing required fields: ${!issuer ? 'issuer' : 'issuanceDate'}`,
        )

      // Schema fetches and permission check share no dependencies — run in parallel
      logger.debug('Fetching schemas and verifying permission in parallel')
      const [schemaRawText, subjectSchemaRawText] = await Promise.all([
        fetchText(schema.id),
        adapter ? adapter.fetchSchema(schemaUrl) : fetchText(schemaUrl),
        verifyPermission(
          trustRegistry,
          schemaId,
          issuanceDate,
          issuer,
          PermissionType.ISSUER,
          logger,
          adapter,
        ),
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

      const ecsType = identifySchema(subjectSchema)

      // ECS Trust Registry whitelist enforcement.
      //
      // When the credential's underlying JSON Schema is one of the four
      // Essential Credential Schemas (Service / Organization / Persona /
      // UserAgent) AND the matched registry declares a non-empty
      // `allowedEcsEcosystems` whitelist, the JSC issuer (i.e. the
      // Ecosystem DID that owns the schema; available as
      // `w3cCredential.issuer` in this recursive call) MUST appear in
      // the whitelist. When the registry declares no whitelist (or an
      // empty one), any Ecosystem DID is accepted — preserving the
      // pre-feature behaviour for backward compatibility.
      if (ecsType !== null && registry?.allowedEcsEcosystems && registry.allowedEcsEcosystems.length > 0) {
        const jscIssuer =
          typeof w3cCredential.issuer === 'string'
            ? w3cCredential.issuer
            : (w3cCredential.issuer as { id?: string } | undefined)?.id
        if (!jscIssuer || !registry.allowedEcsEcosystems.includes(jscIssuer)) {
          throw new TrustError(
            TrustErrorCode.ECS_TRUST_REGISTRY_NOT_WHITELISTED,
            `Ecosystem DID ${jscIssuer ?? '<unknown>'} is not whitelisted to issue ${ecsType} schemas in registry ${registry.id}`,
          )
        }
        logger.debug('ECS ecosystem whitelist passed', { jscIssuer, ecsType, registryId: registry.id })
      }

      const credential = {
        schemaType: ecsType,
        id,
        issuer,
        ...attrs,
      } as ICredential
      return { credential, outcome }
    } catch (error) {
      logger.error('Failed to process credential', error)
      // Preserve specific TrustError codes (e.g. ECS_TRUST_REGISTRY_NOT_WHITELISTED)
      // raised explicitly above. Otherwise wrap with the legacy coarse code so
      // existing consumers keep their behaviour.
      if (error instanceof TrustError) throw error
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
 * Verifies that an entity holds valid permissions for the specified schema
 * and ensures the credential's issuance date is not earlier than the permission creation date.
 */
async function verifyPermission(
  trustRegistry: string,
  schemaId: string,
  issuanceDate: string,
  did: string,
  permissionType: PermissionType,
  logger: IVerreLogger,
  adapter?: IRegistryAdapter,
) {
  logger.debug('Verifying permission', { schemaId, did, hasAdapter: !!adapter })

  let perm:
    | { type: string; created: string; effective_from?: string | null; effective_until?: string | null }
    | undefined

  if (adapter) {
    logger.debug('Using registry adapter for permission check', { schemaId, did })
    perm = await adapter.fetchPermission(schemaId, did, permissionType)
  } else {
    const permUrl = `${toIndexerUrl(trustRegistry)}/perm/v1/list?did=${encodeURIComponent(
      did,
    )}&type=${permissionType}&response_max_size=1&schema_id=${schemaId}`
    logger.debug('Fetching issuer permissions', { permUrl, schemaId })
    const permResponse = await fetchJson<PermissionResponse>(permUrl)
    perm = permResponse.permissions?.[0]
  }

  if (!perm || perm.type !== permissionType)
    throw new TrustError(
      TrustErrorCode.INVALID_PERMISSIONS,
      `No valid ${permissionType} permissions were found for the specified DID: ${did} for schema ${schemaId}`,
    )

  const effectiveFrom = perm.effective_from ?? perm.created
  const effectiveUntil = perm.effective_until ?? new Date().toISOString()
  logger.debug('Permission found, verifying dates', {
    did,
    issuanceDate,
    effectiveFrom,
    effectiveUntil,
  })
  const issuanceTs = Date.parse(issuanceDate)
  const effectiveFromTs = Date.parse(effectiveFrom)
  const effectiveUntilTs = Date.parse(effectiveUntil)
  if (issuanceTs < effectiveFromTs || issuanceTs > effectiveUntilTs) {
    throw new TrustError(
      TrustErrorCode.INVALID_PERMISSIONS,
      `Credential issuance date (${issuanceDate}) is not within the permission effective range (${effectiveFrom} - ${effectiveUntil})`,
    )
  }

  logger.debug('Permission verified successfully', { did, schemaId })
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
