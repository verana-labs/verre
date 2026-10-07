// Byte-exact copies of the JSON Schema documents that a credentialSchema pins with a digestSRI.
// The digest covers the raw bytes, so each copy must keep the exact formatting of the published document.

/**
 * https://www.w3.org/ns/credentials/json-schema/v2.json as w3.org serves it (Last-Modified: 2025-03-19).
 * digestSRI: sha384-FdPKzKLFNWo+3ZqV9vjuY8aNQk+636lvGRKKNzAfy93Q9jf+lNHD8j91g/KHWCBX
 */
export const JSON_SCHEMA_CREDENTIAL_V2 =
  '{\n  "$schema": "https://json-schema.org/draft/2020-12/schema",\n  "$id": "https://www.w3.org/2022/credentials/v2/json-schema-credential-schema.json",\n  "description": "JSON Schema for a Verifiable Credential of type JsonSchemaCredential according to the Verifiable Credentials Data Model v2",\n  "type": "object",\n  "properties": {\n    "type": {\n      "type": "array",\n      "const": [\n        "VerifiableCredential",\n        "JsonSchemaCredential"\n      ]\n    },\n    "credentialSubject": {\n      "type": "object",\n      "properties": {\n        "type": {\n          "type": "string",\n          "const": "JsonSchema"\n        },\n        "jsonSchema": {\n          "$ref": "https://json-schema.org/draft/2020-12/schema"\n        }\n      },\n      "required": [\n        "type",\n        "jsonSchema"\n      ]\n    },\n    "credentialSchema": {\n      "type": "object",\n      "properties": {\n        "id": {\n          "type": "string",\n          "const": "https://www.w3.org/ns/credentials/json-schema/v2.json"\n        },\n        "type": {\n          "type": "string",\n          "const": "JsonSchema"\n        },\n        "digestSRI": {\n          "type": "string"\n        }\n      },\n      "required": [\n        "id",\n        "type",\n        "digestSRI"\n      ]\n    }\n  },\n  "required": [\n    "type",\n    "credentialSubject",\n    "credentialSchema"\n  ]\n}'

/**
 * Bundled JSON Schema documents, keyed by the URL that a credentialSchema uses to reference them.
 * `fetchSchemaText` serves a bundled copy without network access when it matches the pinned digestSRI.
 */
export const DEFAULT_SCHEMAS: Record<string, string> = {
  'https://www.w3.org/ns/credentials/json-schema/v2.json': JSON_SCHEMA_CREDENTIAL_V2,
}
