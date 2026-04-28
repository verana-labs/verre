import { DIDDocument, Resolver } from 'did-resolver'

// types
export type TrustResolution = {
  didDocument?: DIDDocument
  verified: boolean
  outcome: TrustResolutionOutcome
  metadata?: TrustResolutionMetadata
  /**
   * The Service credential extracted from a successfully resolved
   * Verifiable Trust Credential (VTC). Preserved for backward
   * compatibility; equivalent to the first ECS-SERVICE entry of
   * `validPresentations`.
   */
  service?: IService
  /**
   * The Service Provider credential (ECS-ORG or ECS-PERSONA) extracted
   * from a successfully resolved VTC. Preserved for backward
   * compatibility; equivalent to the first ECS-ORG/ECS-PERSONA entry
   * of `validPresentations`.
   */
  serviceProvider?: ICredential
  /**
   * All linked-vp service entries that were successfully dereferenced
   * AND whose credentials passed verification. May overlap with
   * `invalidPresentations` (same VP URL) when a multi-credential VP
   * is partially valid: each credential is evaluated independently.
   */
  validPresentations?: VpOutcome[]
  /**
   * All linked-vp service entries that failed at least one validation
   * step. Entries are grouped by error code per VP; a partially-valid
   * VP appears here with the IDs of the failing credentials, while
   * its passing credentials appear in `validPresentations`.
   */
  invalidPresentations?: VpOutcomeWithError[]
}

export type CredentialResolution = {
  verified: boolean
  outcome: TrustResolutionOutcome
  issuer: string
}

export type ResolverConfig = {
  verifiablePublicRegistries?: VerifiablePublicRegistry[]
  didResolver?: Resolver
  cache?: TrustResolutionCache<string, Promise<TrustResolution>>
  skipDigestSRICheck?: boolean
  logger?: IVerreLogger
}

export type VerifyPermissionsOptions = {
  did: string
  jsonSchemaCredentialId: string
  issuanceDate: string
  verifiablePublicRegistries: VerifiablePublicRegistry[]
  permissionType: PermissionType
  logger?: IVerreLogger
}

export type InternalResolverConfig = Omit<ResolverConfig, 'didResolver'> & {
  didResolver: Resolver
  attrs?: IService
}

/**
 * Adapter interface for resolving registry operations locally, without making HTTP calls.
 * Intended for use when verre runs inside the same process as the registry (e.g., the indexer).
 */
export interface IRegistryAdapter {
  /**
   * Fetches a schema by URL. Replaces the HTTP fetchText call for the subject schema.
   */
  fetchSchema(url: string): Promise<string>
  /**
   * Fetches the permission for a given DID and schema. Replaces the HTTP call to /perm/v1/list.
   * Return undefined if no permission exists (verre will throw INVALID_PERMISSIONS).
   */
  fetchPermission(
    schemaId: string,
    did: string,
    permissionType: PermissionType,
  ): Promise<Pick<Permission, 'type' | 'created' | 'effective_from' | 'effective_until'> | undefined>
}

export type VerifiablePublicRegistry = {
  /**
   * Canonical identifier of the registry, used as a URL prefix to match
   * `$ref` references in credential schemas (e.g. `vpr:verana:vna-testnet-1`).
   */
  id: string
  /**
   * Alternative HTTP base URLs used to dereference schemas and permissions
   * from the registry's indexer (e.g. `https://idx.testnet.verana.network/verana`).
   */
  baseUrls: string[]
  /**
   * Marks whether this registry is considered production-grade. A non-production
   * registry yields `TrustResolutionOutcome.VERIFIED_TEST` rather than `VERIFIED`
   * even when validation succeeds.
   */
  production: boolean
  /**
   * Optional in-process adapter for resolving registry operations without HTTP.
   * Useful when verre runs inside the same node as the registry itself.
   */
  adapter?: IRegistryAdapter
  /**
   * Optional whitelist of Ecosystem DIDs trusted to issue ECS-typed
   * Verifiable Trust JSON Schema Credentials (VTJSCs) inside this registry.
   *
   * - When **omitted or empty**, any Ecosystem within this registry may issue
   *   ECS schemas (current behaviour, fully backward compatible).
   * - When **set**, an ECS-typed VTC whose underlying VTJSC is issued by an
   *   Ecosystem DID NOT in this list is rejected with
   *   `TrustErrorCode.ECS_TRUST_REGISTRY_NOT_WHITELISTED`.
   *
   * Only applies to ECS-typed credentials; non-ECS credentials are unaffected.
   */
  allowedEcsEcosystems?: string[]
}

/**
 * Classification of a Linked Verifiable Presentation (linked-vp) service entry
 * in a DID Document, based on the fragment suffix of its service id.
 *
 * - `VTC`   — Verifiable Trust Credential presentation (`-c-vp` / `-vtc-vp`)
 * - `VTJSC` — Verifiable Trust JSON Schema Credential presentation
 *             (`-jsc-vp` / `-vtjsc-vp`)
 */
export enum PresentationType {
  VTC = 'vtc',
  VTJSC = 'vtjsc',
}

/**
 * A linked-vp service entry that was successfully dereferenced and yielded
 * at least one valid credential.
 */
export type VpOutcome = {
  /** Service entry id from the DID Document (e.g. `did:web:foo#vpr-schemas-service-c-vp`). */
  serviceId: string
  /** Resolved VP URL (the dereferenced `serviceEndpoint`). */
  vpUrl: string
  /** Classification of the linked-vp fragment. */
  presentationType: PresentationType
  /** IDs of the credentials inside the VP that passed verification. */
  credentialIds: string[]
}

/**
 * A linked-vp service entry that failed at least one validation step.
 *
 * For VP-level failures (e.g. `DEREFERENCE_FAILED`, `VP_SIGNATURE_INVALID`)
 * `credentialIds` is empty and `presentationType` may be `undefined` if the
 * fragment itself was non-conformant.
 *
 * For per-credential failures inside an otherwise valid VP, `credentialIds`
 * lists the IDs that failed with `errorCode`. The valid credentials of the
 * same VP are reported separately under `validPresentations`.
 */
export type VpOutcomeWithError = {
  /** Service entry id from the DID Document. */
  serviceId: string
  /** Resolved VP URL when known; may equal the service id for fragment errors. */
  vpUrl: string
  /** Classification of the linked-vp fragment, if it could be classified. */
  presentationType?: PresentationType
  /** IDs of credentials that failed with `errorCode`; empty for VP-level errors. */
  credentialIds: string[]
  /** Fine-grained error code; see `TrustErrorCode`. */
  errorCode: TrustErrorCode
  /** Human-readable diagnostic. */
  errorMessage: string
}

export type DidDocumentResult = {
  credentials: ICredential[]
}

export type TrustResolutionMetadata = {
  errorMessage?: string
  errorCode?: TrustErrorCode
}

export type Permission = {
  id: number
  schema_id: number
  type: PermissionType
  grantee: string
  did?: string
  country?: string
  validator_perm_id?: number
  created: string
  created_by: string
  modified: string
  extended?: number | null
  extended_by?: string | null
  effective_from?: string | null
  effective_until?: string | null
  revoked?: number | null
  revoked_by?: string | null
  terminated?: number | null
  terminated_by?: string | null
  validation_fees: number
  issuance_fees: number
  verification_fees: number
  deposit: number
  slashed?: number | null
  slashed_by?: string | null
  repaid?: number | null
  repaid_by?: string | null
  slashed_deposit?: number | null
  repaid_deposit?: number | null
  vp_state: VerifiablePresentationState
  vp_exp?: number | null
  vp_last_state_change: number | null
  vp_validator_deposit?: number
  vp_current_fees: number
  vp_current_deposit: number
  vp_summary_digest_sri?: string | null
  vp_term_requested?: number | null
}

// Enums
export enum ECS {
  ORG = 'ecs-org',
  PERSONA = 'ecs-persona',
  SERVICE = 'ecs-service',
  USER_AGENT = 'ecs-user-agent',
}

export enum PermissionType {
  ISSUER = 'ISSUER',
  VERIFIER = 'VERIFIER',
  ISSUER_GRANTOR = 'ISSUER_GRANTOR',
  VERIFIER_GRANTOR = 'VERIFIER_GRANTOR',
  TRUST_REGISTRY = 'TRUST_REGISTRY',
  HOLDER = 'HOLDER',
}

export enum PermissionManagementMode {
  OPEN = 'OPEN',
  GRANTOR_VALIDATION = 'GRANTOR_VALIDATION',
  TRUST_REGISTRY_VALIDATION = 'TRUST_REGISTRY_VALIDATION',
}

export enum VerifiablePresentationState {
  PENDING = 'PENDING',
  VALIDATED = 'VALIDATED',
  TERMINATED = 'TERMINATED',
}

/**
 * Fine-grained error codes emitted by verre during trust resolution.
 *
 * The first set of values (lowercase, snake_case) are the historical
 * coarse-grained codes preserved for backward compatibility with existing
 * downstream consumers (e.g. the verana-resolver). The second set
 * (UPPER_SNAKE_CASE) are the new per-VP / per-credential codes attached
 * to entries of `TrustResolution.invalidPresentations` and to
 * `TrustResolutionMetadata` when a more specific cause is known.
 *
 * New codes are emitted by the per-VP error path inside
 * `processDidDocument`; the existing throw-sites in `didValidator` continue
 * to raise the legacy coarse codes so external behaviour is unchanged.
 */
export enum TrustErrorCode {
  // --- Legacy coarse codes (backward compatible) ---
  INVALID = 'invalid',
  NOT_FOUND = 'not_found',
  NOT_SUPPORTED = 'not_supported',
  INVALID_PERMISSIONS = 'invalid_permissions',
  INVALID_REQUEST = 'invalid_request',
  SCHEMA_MISMATCH = 'schema_mismatch',
  VERIFICATION_FAILED = 'verification_failed',

  // --- Fine-grained VP-level codes ---
  /** The fragment portion of the linked-vp service id is not recognised. */
  FRAGMENT_NOT_CONFORMANT = 'FRAGMENT_NOT_CONFORMANT',
  /** The VP `serviceEndpoint` could not be dereferenced (HTTP/network error). */
  DEREFERENCE_FAILED = 'DEREFERENCE_FAILED',
  /** The dereferenced document is not a valid Verifiable Presentation. */
  VP_INVALID_FORMAT = 'VP_INVALID_FORMAT',
  /** The VP signature could not be verified. */
  VP_SIGNATURE_INVALID = 'VP_SIGNATURE_INVALID',
  /** The VP holder DID does not match the DID being resolved. */
  VP_HOLDER_MISMATCH = 'VP_HOLDER_MISMATCH',
  /** The VP contains zero credentials. */
  VP_NO_CREDENTIALS = 'VP_NO_CREDENTIALS',

  // --- Fine-grained credential-level codes ---
  /** The credential signature could not be verified. */
  CREDENTIAL_SIGNATURE_INVALID = 'CREDENTIAL_SIGNATURE_INVALID',
  /** The credential is missing required fields (e.g. `credentialSchema`). */
  CREDENTIAL_INVALID_FORMAT = 'CREDENTIAL_INVALID_FORMAT',
  /** The credential's claimed schema could not be dereferenced. */
  SCHEMA_NOT_FOUND = 'SCHEMA_NOT_FOUND',
  /** The credential payload does not validate against its declared schema. */
  CREDENTIAL_SCHEMA_MISMATCH = 'CREDENTIAL_SCHEMA_MISMATCH',
  /** The schema digest stored in the credential does not match the fetched schema. */
  SCHEMA_DIGEST_MISMATCH = 'SCHEMA_DIGEST_MISMATCH',
  /** The issuer lacks an active ISSUER permission for the credential's schema. */
  ISSUER_PERMISSION_MISSING = 'ISSUER_PERMISSION_MISSING',
  /** The issuer's permission is not effective at the credential's issuance date. */
  ISSUER_PERMISSION_NOT_EFFECTIVE = 'ISSUER_PERMISSION_NOT_EFFECTIVE',

  // --- Fine-grained ECS / Trust Registry codes ---
  /**
   * The Ecosystem DID that issued an ECS VTJSC is not in the registry's
   * `allowedEcsEcosystems` whitelist (see `VerifiablePublicRegistry`).
   */
  ECS_TRUST_REGISTRY_NOT_WHITELISTED = 'ECS_TRUST_REGISTRY_NOT_WHITELISTED',
  /** The credential references a registry not configured in `verifiablePublicRegistries`. */
  REGISTRY_NOT_CONFIGURED = 'REGISTRY_NOT_CONFIGURED',
}

/**
 * Indicates the trust evaluation result of resolving verifiable public registries.
 * Used to determine if the data is verified, test-only, not trustworthy, or failed to validate.
 */
export enum TrustResolutionOutcome {
  VERIFIED = 'verified', // At least one production registry was found.
  VERIFIED_TEST = 'verified-test', // Only non-production registries were found.
  NOT_TRUSTED = 'not-trusted', // The credential is structurally valid, but not from a trusted source.
  INVALID = 'invalid', // The process failed or the credential is invalid.
}

export enum LogLevel {
  NONE = 'none',
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error',
}

// interfaces
export interface PermissionResponse {
  permissions: Permission[]
}

export interface BaseCredential {
  schemaType: ECS | 'unknown'
  id: string
  issuer: string
}

export interface IOrg extends BaseCredential {
  schemaType: typeof ECS.ORG
  name: string
  logo: string
  registryId: string
  registryUri?: string
  address: string
  countryCode: string
  legalJurisdiction?: string
  lei?: string
  organizationKind?: string
}

export interface IPersona extends BaseCredential {
  schemaType: typeof ECS.PERSONA
  name: string
  avatar?: string
  controllerCountryCode: string
  controllerJurisdiction?: string
  description?: string
  descriptionFormat?: string
}

export interface IService extends BaseCredential {
  schemaType: typeof ECS.SERVICE
  name: string
  type: string
  description: string
  descriptionFormat?: string
  logo: string
  minimumAgeRequired: number
  termsAndConditions: string
  termsAndConditionsDigestSri?: string
  privacyPolicy: string
  privacyPolicyDigestSri?: string
}

export interface IUserAgent extends BaseCredential {
  schemaType: typeof ECS.USER_AGENT
  version: string
  build?: string
}

export interface IUnknownCredential extends BaseCredential {
  schemaType: 'unknown'
  [key: string]: any
}

export type ICredential = IOrg | IPersona | IService | IUserAgent | IUnknownCredential

export interface IVerreLogger {
  debug(message: string, meta?: Record<string, unknown>): void
  info(message: string, meta?: Record<string, unknown>): void
  warn(message: string, meta?: Record<string, unknown>): void
  error(message: string, error?: Error | unknown): void
}

export interface TrustResolutionCache<K, V> {
  get(key: K): V | undefined
  set(key: K, value: V): void
  delete(key: K): void
  clear(): void
}
