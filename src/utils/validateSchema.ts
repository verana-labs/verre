import Ajv, { JSONSchemaType } from 'ajv/dist/2020'
import addFormats from 'ajv-formats'

import { ECS, TrustErrorCode } from '../types'

import { essentialSchemas } from './data'
import { TrustError } from './trustError'

/**
 * Loads a predefined essential schema by name.
 *
 * @param schemaName - The key of the schema to load.
 * @returns The corresponding schema from `essentialSchemas`.
 */
export const loadSchema = (schemaName: keyof typeof essentialSchemas) => {
  return essentialSchemas[schemaName]
}

/**
 * Preloads essential schemas into a structured object.
 */
const schemas = {
  [ECS.ORG]: loadSchema(ECS.ORG),
  [ECS.PERSON]: loadSchema(ECS.PERSON),
  [ECS.SERVICE]: loadSchema(ECS.SERVICE),
  [ECS.USER_AGENT]: loadSchema(ECS.USER_AGENT),
}

/**
 * Identifies the appropriate schema for a given verifiable presentation (VP).
 *
 * Uses Ajv to validate the `credentialSubject` against predefined schemas.
 *
 * @param vp - The verifiable presentation to check.
 * @returns The matching schema name or `null` if no match is found.
 */
export const identifySchema = (vp: any): ECS | null => {
  const ajv = new Ajv({ strict: false })
  addFormats(ajv)
  for (const schemaName of Object.keys(schemas) as ECS[]) {
    const validate = ajv.compile(schemas[schemaName].properties.credentialSubject)
    if (validate(vp)) {
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
