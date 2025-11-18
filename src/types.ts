import type { AgentContext } from '@credo-ts/core'

import { DIDDocument, Resolver } from 'did-resolver'

// types
export type TrustResolution = {
  didDocument?: DIDDocument
  verified: boolean
  outcome: TrustResolutionOutcome
  metadata?: TrustResolutionMetadata
  service?: IService
  serviceProvider?: ICredential
}

export type ResolverConfig = {
  verifiablePublicRegistries?: VerifiablePublicRegistry[]
  didResolver?: Resolver
  agentContext: AgentContext
}

export type InternalResolverConfig = ResolverConfig & {
  attrs?: IService
}

export type VerifiablePublicRegistry = {
  id: string
  baseUrls: string[]
  production: boolean
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
  did?: string
  grantee: string
  created: string
  created_by: string
  extended: number
  extended_by: string
  effective_from?: string
  effective_until?: string
  modified: string
  validation_fees: number
  issuance_fees: number
  verification_fees: number
  deposit: number
  revoked?: number
  revoked_by: string
  terminated?: number
  terminated_by: string
  country?: string
  validator_perm_id?: number
  vp_state: VerifiablePresentationState
  vp_exp?: number
  vp_last_state_change: number
  vp_validator_deposit?: number
  vp_current_fees: number
  vp_current_deposit: number
  vp_summary_digest_sri?: string
  vp_term_requested?: number
}

// Enums
export enum ECS {
  ORG = 'ecs-org',
  PERSON = 'ecs-person',
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
  TERMINATION_REQUESTED = 'TERMINATION_REQUESTED',
}

export enum TrustErrorCode {
  INVALID = 'invalid',
  NOT_FOUND = 'not_found',
  NOT_SUPPORTED = 'not_supported',
  INVALID_ISSUER = 'invalid_issuer',
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

// interfaces
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
  registryUrl: string
  address: string
  type: string
  countryCode: string
}

export interface IPerson extends BaseCredential {
  schemaType: typeof ECS.PERSON
  firstName: string
  lastName: string
  avatar: string
  birthDate: string
  countryOfResidence: string
}

export interface IService extends BaseCredential {
  schemaType: typeof ECS.SERVICE
  name: string
  type: string
  description: string
  logo: string
  minimumAgeRequired: number
  termsAndConditions: string
  termsAndConditionsHash?: string
  privacyPolicy: string
  privacyPolicyHash?: string
}

export interface IUserAgent extends BaseCredential {
  schemaType: typeof ECS.USER_AGENT
  name: string
  description: string
  category: string
  wallet: string
  logo: string
  termsAndConditions: string
  termsAndConditionsHash?: string
  privacyPolicy: string
  privacyPolicyHash?: string
}

export interface IUnknownCredential extends BaseCredential {
  schemaType: 'unknown'
  [key: string]: any
}

export type ICredential = IOrg | IPerson | IService | IUserAgent | IUnknownCredential
