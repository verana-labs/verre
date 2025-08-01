import type { AgentContext, W3cPresentation } from '@credo-ts/core'

import { DIDDocument, Resolver, ServiceEndpoint } from 'did-resolver'

// types
export type TrustResolution = {
  didDocument?: DIDDocument
  verified: boolean
  metadata?: TrustResolutionMetadata
  service?: IService
  serviceProvider?: ICredential
}

export type ResolverConfig = {
  trustRegistryUrl?: string
  didResolver?: Resolver
  agentContext: AgentContext
}

export type InternalResolverConfig = ResolverConfig & {
  attrs?: IService
}

export type ServiceWithCredential = {
  id: string
  type: string
  serviceEndpoint: ServiceEndpoint | ServiceEndpoint[]
  verifiablePresentation?: W3cPresentation
}

export type DidDocumentResult = {
  credentials: ICredential[]
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

// interfaces
export interface Permission {
  id: number
  schema_id: number
  type: PermissionType
  did?: string
  grantee: string
  created: number
  created_by: string
  extended: number
  extended_by: string
  effective_from?: number
  effective_until?: number
  modified: number
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

export interface TrustResolutionMetadata {
  errorMessage?: string
  errorCode?: TrustErrorCode
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
