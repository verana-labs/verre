export enum ECS {
  ORG = "ecs-org.json",
  PERSON = "ecs-person.json",
  SERVICE = "ecs-service.json",
  USER_AGENT = "ecs-user-agent.json",
}

export type ResolveResult = {
  result: boolean;
  didDocument?: any;
  message?: string;
};