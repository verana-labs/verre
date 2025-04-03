import Ajv, { JSONSchemaType } from 'ajv/dist/2020'
import addFormats from 'ajv-formats'

import { ECS, TrustErrorCode } from '../types'

import { essentialSchemas } from './data'
import { TrustError } from './trustError'

export const loadSchema = (schemaName: keyof typeof essentialSchemas) => {
  return essentialSchemas[schemaName]
}

const schemas = {
  [ECS.ORG]: loadSchema(ECS.ORG),
  [ECS.PERSON]: loadSchema(ECS.PERSON),
  [ECS.SERVICE]: loadSchema(ECS.SERVICE),
  [ECS.USER_AGENT]: loadSchema(ECS.USER_AGENT),
}

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

export const checkSchemaMatch = (vp: any): ECS | null => {
  for (const [schemaName, schema] of Object.entries(schemas) as [ECS, any][]) {
    if (vp === JSON.stringify(schema)) {
      return schemaName
    }
  }
  return null
}

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
