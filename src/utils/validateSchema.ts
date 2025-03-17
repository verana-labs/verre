import Ajv2020 from 'ajv/dist/2020.js'
import addFormatsModule from 'ajv-formats'
import { readFileSync } from 'fs'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

import { ECS } from '../types.js'

const Ajv = Ajv2020.default
const addFormats = addFormatsModule.default
const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const ajv = new Ajv({ strict: false })
addFormats(ajv)

export const loadSchema = (schemaName: string) => {
  const schemaPath = join(__dirname, `../../public/schemas/${schemaName}`)
  return JSON.parse(readFileSync(schemaPath, 'utf-8'))
}

const schemas = {
  [ECS.ORG]: loadSchema(ECS.ORG),
  [ECS.PERSON]: loadSchema(ECS.PERSON),
  [ECS.SERVICE]: loadSchema(ECS.SERVICE),
  [ECS.USER_AGENT]: loadSchema(ECS.USER_AGENT),
}

export const identifySchema = (vp: any): ECS | null => {
  for (const schemaName of Object.keys(schemas) as ECS[]) {
    const validate = ajv.compile(schemas[schemaName])
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
