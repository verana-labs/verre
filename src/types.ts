import { DIDDocument } from "did-resolver";

export enum ECS {
  ORG = "ecs-org.json",
  PERSON = "ecs-person.json",
  SERVICE = "ecs-service.json",
  USER_AGENT = "ecs-user-agent.json",
}

export type ResolveResult = {
  result: boolean;
  didDocument?: DIDDocument;
  message?: string;
};

export enum PermissionManagementMode {
  OPEN = "OPEN",
  GRANTOR_VALIDATION = "GRANTOR_VALIDATION",
  TRUST_REGISTRY_VALIDATION = "TRUST_REGISTRY_VALIDATION"
}

export interface CredentialSchema {
  id: number;
  tr_id: number;
  created: string;
  modified: string;
  archived: string;
  deposit: number;
  json_schema: string;
  issuer_grantor_validation_validity_period: number;
  verifier_grantor_validation_validity_period: number;
  issuer_validation_validity_period: number
  verifier_validation_validity_period: number;
  holder_validation_validity_period: number;
  issuer_perm_management_mode: PermissionManagementMode;
  verifier_perm_management_mode: PermissionManagementMode;
}
