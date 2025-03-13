import { DIDDocument } from 'did-resolver'

export enum ECS {
  ORG = 'ecs-org.json',
  PERSON = 'ecs-person.json',
  SERVICE = 'ecs-service.json',
  USER_AGENT = 'ecs-user-agent.json',
}

export type ResolveResult = {
  result: boolean
  didDocument?: DIDDocument
  message?: string
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
