import { base64 } from '@scure/base'
import Ajv, { JSONSchemaType } from 'ajv/dist/2020'
import addFormats from 'ajv-formats'
import canonicalize from 'canonicalize'

import { ECS, TrustErrorCode } from '../types'

import { hash } from './crypto'
import { TrustError } from './trustError'

/**
 * Reference SHA-384 SRI digests for each Essential Credential Schema.
 * The $id property is excluded before hashing (it varies per deployment).
 */
const ECS_SCHEMA_DIGESTS: Record<string, string> = {
  [ECS.SERVICE]: 'sha384-PVseqJJjEGMVRcht77rE2yLqRnCiLBRLOklSuAshSEXK3eyITmUpDBhpQryJ/XIx',
  [ECS.ORG]: 'sha384-XF10SsOaav+i+hBaXP29coZWZeaCZocFvfP9ZeHh9B7++q7YGA2QLTbFZqtYs/zA',
  [ECS.PERSONA]: 'sha384-4vkQl6Ro6fudr+g5LL2NQJWVxaSTaYkyf0yVPVUmzA2leNNn0sJIsM07NlOAG/2I',
  [ECS.USER_AGENT]: 'sha384-yLRK2mCokVjRlGX0nVzdEYQ1o6YWpQqgdg6+HlSxCePP+D7wvs0+70TJACLZfbF/',
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
