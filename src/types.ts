import type { W3cPresentation } from '@credo-ts/core'

import { DIDDocument, Resolver, ServiceEndpoint } from 'did-resolver'

// types
export type TrustResolution = {
  didDocument?: DIDDocument
  metadata: TrustResolutionMetadata
  verifiableService?: IService
  issuerCredential?: ICredential
}

export type ResolverConfig = {
  trustRegistryUrl?: string
  didResolver?: Resolver
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

export enum TrustStatus {
  RESOLVED = 'resolved',
  ERROR = 'error',
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
export interface CredentialSchema {
  id: number
  tr_id: number
  created: string
  modified: string
  archived: string
  deposit: number
  json_schema: string
  issuer_grantor_validation_validity_period: number
  verifier_grantor_validation_validity_period: number
  issuer_validation_validity_period: number
  verifier_validation_validity_period: number
  holder_validation_validity_period: number
  issuer_perm_management_mode: PermissionManagementMode
  verifier_perm_management_mode: PermissionManagementMode
}

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
  status: TrustStatus
  errorCode?: TrustErrorCode
}

export interface BaseCredential {
  type: ECS | 'unknown'
  issuer: string
  credentialSubject: Record<string, unknown>
}

export interface IOrg extends BaseCredential {
  type: typeof ECS.ORG
  credentialSubject: {
    name: string
    logo: string
    registryId: string
    registryUrl: string
    address: string
    type: string
    countryCode: string
  }
}

export interface IPerson extends BaseCredential {
  type: typeof ECS.PERSON
  credentialSubject: {
    firstName: string
    lastName: string
    avatar: string
    birthDate: string
    countryOfResidence: string
  }
}

export interface IService extends BaseCredential {
  type: typeof ECS.SERVICE
  credentialSubject: {
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
}

export interface IUserAgent extends BaseCredential {
  type: typeof ECS.USER_AGENT
  credentialSubject: {
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
}

export interface IUnknownCredential extends BaseCredential {
  type: 'unknown'
  credentialSubject: {
    [key: string]: any
  }
}

export type ICredential = IOrg | IPerson | IService | IUserAgent | IUnknownCredential
