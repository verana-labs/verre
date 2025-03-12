import Ajv from "ajv/dist/2020";
import addFormats from "ajv-formats";
import fs from "fs";
import path from "path";
import { ECS } from '../types'

const ajv = new Ajv();
addFormats(ajv);

export const loadSchema = (schemaName: string) => {
  const schemaPath = path.join(__dirname, `../../public/schemas/${schemaName}`);
  return JSON.parse(fs.readFileSync(schemaPath, "utf-8"));
};

const schemas = {
  [ECS.ORG]: loadSchema(ECS.ORG),
  [ECS.PERSON]: loadSchema(ECS.PERSON),
  [ECS.SERVICE]: loadSchema(ECS.SERVICE),
  [ECS.USER_AGENT]: loadSchema(ECS.USER_AGENT),
};

export const identifySchema = (vp: any): ECS | null => {
  for (const schemaName of Object.keys(schemas) as ECS[]) {
    const validate = ajv.compile(schemas[schemaName]);
    if (validate(vp)) {
      console.log(`✅ VP matches schema: ${schemaName}`);
      return schemaName;
    }
  }
  console.log("❌ VP does not match any known schema.");
  return null;
};

