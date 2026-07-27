import { base64 } from '@scure/base'
import { Ajv2020 as Ajv, type JSONSchemaType } from 'ajv/dist/2020.js'
import _addFormats from 'ajv-formats'
import _canonicalize from 'canonicalize'

// Node16 CJS interop: default import may be the namespace or the value itself
const addFormats = ((_addFormats as any).default ?? _addFormats) as (ajv: InstanceType<typeof Ajv>) => void
const canonicalize = ((_canonicalize as any).default ?? _canonicalize) as (
  input: unknown,
) => string | undefined

import { ECS, TrustErrorCode } from '../types.js'

import { hash } from './crypto.js'
import { TrustError } from './trustError.js'

/**
 * Reference SHA-384 SRI digests for each Essential Credential Schema, from the
 * v4 spec [ECS-EC] table. The $id property is excluded before hashing (it varies
 * per deployment). For the v3 schemas use verre 0.3.x.
 */
const ECS_SCHEMA_DIGESTS: Record<string, string> = {
  [ECS.SERVICE]: 'sha384-0v+BAFGpnBX/RVqH9dUlMglxMrD4AKy4qUtb1lMN4iW9I2gO7XjcUfmGOf0oInP3',
  [ECS.ORG]: 'sha384-UPn4TDqS1nMBAN3FyMzTAZOWp99zBjBD69OjpbhwOKZj7iOrS5qPwJ2SArRz0yzu',
  [ECS.PERSONA]: 'sha384-VfXTfuks02OkoR5USaTfEdc4NU25m4+vNrLATnjC0r0Pn1S3tFTdOvGCfSYdjE2I',
  [ECS.USER_AGENT]: 'sha384-rIWkh3zBD1Ak7CNGpAwZ/ONSmf+ywOYSF3H60ULc9/a1ZYKv6EqiQMJ2dm8dOfjm',
  [ECS.BADGE]: 'sha384-ZxJ2aRpoF/5DJSILWwOES6bmpMg3RZYOfO2CCF8hC/YDNvU+PhCqAnAXq/66nXCq',
}

/**
 * Computes the SRI-style SHA-384 digest of a JSON schema object,
 */
function computeSchemaDigest(schemaObj: Record<string, unknown>): string {
  const { $id, ...schemaWithoutId } = schemaObj

  const canonical = canonicalize(schemaWithoutId)
  if (!canonical) throw new TrustError(TrustErrorCode.SCHEMA_MISMATCH, 'Failed to canonicalize schema')

  const digest = base64.encode(hash('sha384', canonical))
  return `sha384-${digest}`
}

/**
 * Identifies the appropriate schema for a given verifiable presentation (VP).
 *
 * Uses digest to validate the schemaObj against ECS schemas
 *
 * @param schemaObj - The schema to check.
 * @returns The matching schema name or `null` if no match is found.
 */
export const identifySchema = (schemaObj: Record<string, unknown>): ECS | null => {
  const actualDigest = computeSchemaDigest(schemaObj)

  for (const [schemaName, refDigest] of Object.entries(ECS_SCHEMA_DIGESTS) as [ECS, string][]) {
    if (refDigest === actualDigest) {
      return schemaName
    }
  }
  return null
}

/**
 * Validates data against a given JSON schema.
 *
 * Uses Ajv to compile and validate the data. Throws an error if validation fails.
 *
 * @param schema - The JSON schema to validate against.
 * @param data - The data to validate.
 * @returns `true` if the data is valid, otherwise throws an error.
 * @throws {TrustError} If the data does not conform to the schema.
 */
export function validateSchemaContent<T>(schema: JSONSchemaType<T>, data: T): boolean {
  const ajv = new Ajv({ strict: false })
  addFormats(ajv)
  const validate = ajv.compile(schema)
  if (!validate(data))
    throw new TrustError(
      TrustErrorCode.SCHEMA_MISMATCH,
      `Credential does not conform to schema: ${JSON.stringify(validate.errors)}`,
    )
  return true
}
