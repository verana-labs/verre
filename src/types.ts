import type { W3cVerifiableCredential } from '@credo-ts/core'

import { DIDDocument, Resolver } from 'did-resolver'

// types
export type TrustResolution = {
  didDocument?: DIDDocument
  verified: boolean
  outcome: TrustResolutionOutcome
  metadata?: TrustResolutionMetadata
  service?: IService
  serviceProvider?: ICredential
  failedCredentials?: FailedCredential[]
}

export const CREDENTIAL_FORMAT_LDP_VC = 'ldp_vc'

export type FailedCredential = {
  id?: string
  format: string
  error: string
  errorCode: TrustErrorCode
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
  ecsEcosystems?: EcsEcosystem[]
}

export type EcsEcosystem = {
  did: string
  vpr: string
}

export type VerifyParticipantOptions = {
  did: string
  jsonSchemaCredentialId: string
  issuanceDate: string
  verifiablePublicRegistries: VerifiablePublicRegistry[]
  role: ParticipantRole
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
   * Fetches the Participant effective at `when` for a given DID and schema. Replaces the HTTP call
   * to /v4/participant/list. Return undefined if none exists (verre will throw NOT_AUTHORIZED).
   */
  fetchParticipant(
    schemaId: number | string,
    did: string,
    role: ParticipantRole,
    when: string,
  ): Promise<
    | Pick<Participant, 'role' | 'created' | 'effective_from' | 'effective_until' | 'participant_state'>
    | undefined
  >
  /**
   * Resolves the DID of the Ecosystem that created a schema, for the [WL-ECS] allowlist.
   */
  fetchSchemaEcosystemDid(schemaId: number | string): Promise<string | undefined>
}

// [WL-VPR]
export type VerifiablePublicRegistry = {
  id: string
  scheme: string
  api: string[]
  rpc?: string[]
  resolver?: string[]
  version?: string
  production: boolean
  adapter?: IRegistryAdapter
}

export type DidDocumentResult = {
  credentials: ICredential[]
}

export type TrustResolutionMetadata = {
  errorMessage?: string
  errorCode?: TrustErrorCode
}

export type Participant = {
  id: number
  schema_id: number
  role: ParticipantRole
  did: string
  corporation_id: number
  vs_operator: string
  created: string
  adjusted?: string | null
  slashed?: string | null
  repaid?: string | null
  effective_from?: string | null
  effective_until?: string | null
  modified: string
  validation_fees: number
  issuance_fees: number
  verification_fees: number
  deposit: number
  slashed_deposit: number
  repaid_deposit: number
  revoked?: string | null
  validator_participant_id?: number | null
  op_state: OnboardingProcessState
  op_exp?: string | null
  op_last_state_change: string
  op_validator_deposit?: number
  op_current_fees: number
  op_current_deposit: number
  op_summary_digest?: string | null
  issuance_fee_discount: number
  verification_fee_discount: number
  /** Derived by the indexer at the evaluation block, not an on-chain field. */
  participant_state?: ParticipantState
}

// Enums
export enum ECS {
  BADGE = 'ecs-badge',
  ORG = 'ecs-org',
  PERSONA = 'ecs-persona',
  SERVICE = 'ecs-service',
  USER_AGENT = 'ecs-user-agent',
}

export enum ParticipantRole {
  ISSUER = 'ISSUER',
  VERIFIER = 'VERIFIER',
  ISSUER_GRANTOR = 'ISSUER_GRANTOR',
  VERIFIER_GRANTOR = 'VERIFIER_GRANTOR',
  ECOSYSTEM = 'ECOSYSTEM',
  HOLDER = 'HOLDER',
}

// derived by the indexer from the Participant timestamps, in this priority order
export enum ParticipantState {
  REPAID = 'REPAID',
  SLASHED = 'SLASHED',
  REVOKED = 'REVOKED',
  EXPIRED = 'EXPIRED',
  FUTURE = 'FUTURE',
  ACTIVE = 'ACTIVE',
  INACTIVE = 'INACTIVE',
}

export enum OnboardingProcessState {
  PENDING = 'PENDING',
  VALIDATED = 'VALIDATED',
  TERMINATED = 'TERMINATED',
}

export enum TrustErrorCode {
  INVALID = 'invalid',
  NOT_FOUND = 'not_found',
  NOT_SUPPORTED = 'not_supported',
  NOT_AUTHORIZED = 'not_authorized',
  INVALID_REQUEST = 'invalid_request',
  SCHEMA_MISMATCH = 'schema_mismatch',
  VERIFICATION_FAILED = 'verification_failed',
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
export interface ParticipantListResponse {
  participants: Participant[]
}

export interface BaseCredential {
  schemaType: ECS | 'unknown'
  id: string
  issuer: string
  validFrom?: string
  validUntil?: string
  raw?: W3cVerifiableCredential
  digestJCS?: string
}

export interface IOrg extends BaseCredential {
  schemaType: typeof ECS.ORG
  name: string
  logoUri: string
  logoDigestSri: string
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
  avatarUri?: string
  avatarDigestSri?: string
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
  logoUri: string
  logoDigestSri: string
  minimumAgeRequired: number
  termsAndConditionsUri: string
  termsAndConditionsDigestSri: string
  privacyPolicyUri: string
  privacyPolicyDigestSri: string
}

export interface IUserAgent extends BaseCredential {
  schemaType: typeof ECS.USER_AGENT
  version: string
  build?: string
}

export interface IBadge extends BaseCredential {
  schemaType: typeof ECS.BADGE
  badgeNumber: string
  name: string
  photo: string
  title?: string
  department?: string
  birthDate?: number
  biometricPattern?: string
  biometricPatternScheme?: string
}

export interface IUnknownCredential extends BaseCredential {
  schemaType: 'unknown'
  [key: string]: any
}

export type ICredential = IOrg | IPersona | IService | IUserAgent | IBadge | IUnknownCredential

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
