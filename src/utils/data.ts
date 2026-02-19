export const essentialSchemas = {
  'ecs-org': {
    $id: 'https://verana-labs.github.io/verifiable-trust-spec/schemas/v4/org.json',
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    title: 'OrganizationCredential',
    description: 'Identifies a legal organization that operates one or more Verifiable Services.',
    type: 'object',
    properties: {
      credentialSubject: {
        type: 'object',
        properties: {
          id: {
            type: 'string',
            format: 'uri',
            maxLength: 2048,
          },
          name: {
            type: 'string',
            minLength: 1,
            maxLength: 512,
          },
          logo: {
            type: 'string',
            format: 'uri',
            maxLength: 1400000,
            pattern: '^data:image/(png|jpeg|svg\\+xml);base64,',
          },
          registryId: {
            type: 'string',
            minLength: 1,
            maxLength: 256,
          },
          registryUri: {
            type: 'string',
            format: 'uri',
            maxLength: 4096,
          },
          address: {
            type: 'string',
            minLength: 1,
            maxLength: 1024,
          },
          countryCode: {
            type: 'string',
            minLength: 2,
            maxLength: 2,
            pattern: '^[A-Z]{2}$',
          },
          legalJurisdiction: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '^[A-Z]{2}(-[A-Z0-9]{1,3})?$',
          },
          lei: {
            type: 'string',
            pattern: '^[A-Z0-9]{20}$',
          },
          organizationKind: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
          },
        },
        required: ['id', 'name', 'logo', 'registryId', 'address', 'countryCode'],
      },
    },
  },
  'ecs-persona': {
    $id: 'https://verana-labs.github.io/verifiable-trust-spec/schemas/v4/persona.json',
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    title: 'PersonaCredential',
    description:
      'Identifies a Persona (human-controlled avatar) that operates one or more Verifiable Services.',
    type: 'object',
    properties: {
      credentialSubject: {
        type: 'object',
        properties: {
          id: {
            type: 'string',
            format: 'uri',
            maxLength: 2048,
          },
          name: {
            type: 'string',
            minLength: 1,
            maxLength: 256,
          },
          avatar: {
            type: 'string',
            format: 'uri',
            maxLength: 1400000,
            pattern: '^data:image/(png|jpeg|svg\\+xml);base64,',
          },
          controllerCountryCode: {
            type: 'string',
            minLength: 2,
            maxLength: 2,
            pattern: '^[A-Z]{2}$',
          },
          controllerJurisdiction: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '^[A-Z]{2}(-[A-Z0-9]{1,3})?$',
          },
          description: {
            type: 'string',
            minLength: 0,
            maxLength: 16384,
          },
          descriptionFormat: {
            type: 'string',
            enum: ['text/plain', 'text/markdown'],
            default: 'text/plain',
          },
        },
        required: ['id', 'name', 'controllerCountryCode'],
      },
    },
  },
  'ecs-service': {
    $id: 'https://verana-labs.github.io/verifiable-trust-spec/schemas/v4/service.json',
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    title: 'ServiceCredential',
    description:
      'Identifies a Verifiable Service and defines the minimum trust and access requirements required to interact with it.',
    type: 'object',
    properties: {
      credentialSubject: {
        type: 'object',
        properties: {
          id: {
            type: 'string',
            format: 'uri',
            maxLength: 2048,
          },
          name: {
            type: 'string',
            minLength: 1,
            maxLength: 512,
          },
          type: {
            type: 'string',
            minLength: 1,
            maxLength: 128,
          },
          description: {
            type: 'string',
            maxLength: 4096,
          },
          descriptionFormat: {
            type: 'string',
            enum: ['text/plain', 'text/markdown'],
            default: 'text/plain',
          },
          logo: {
            type: 'string',
            format: 'uri',
            maxLength: 1400000,
            pattern: '^data:image/(png|jpeg|svg\\+xml);base64,',
          },
          minimumAgeRequired: {
            type: 'integer',
            minimum: 0,
            maximum: 255,
          },
          termsAndConditions: {
            type: 'string',
            format: 'uri',
            maxLength: 4096,
          },
          termsAndConditionsDigestSri: {
            type: 'string',
            maxLength: 256,
          },
          privacyPolicy: {
            type: 'string',
            format: 'uri',
            maxLength: 4096,
          },
          privacyPolicyDigestSri: {
            type: 'string',
            maxLength: 256,
          },
        },
        required: [
          'id',
          'name',
          'type',
          'description',
          'logo',
          'minimumAgeRequired',
          'termsAndConditions',
          'privacyPolicy',
        ],
      },
    },
  },
  'ecs-user-agent': {
    $id: 'https://verana-labs.github.io/verifiable-trust-spec/schemas/v4/ua.json',
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    title: 'UserAgentCredential',
    description:
      'Identifies a User Agent instance and the software version it runs. The issuer identifies the software product line.',
    type: 'object',
    properties: {
      credentialSubject: {
        type: 'object',
        properties: {
          id: {
            type: 'string',
            format: 'uri',
            maxLength: 2048,
          },
          version: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
          },
          build: {
            type: 'string',
            minLength: 1,
            maxLength: 128,
          },
        },
        required: ['id', 'version'],
      },
    },
  },
} as const
