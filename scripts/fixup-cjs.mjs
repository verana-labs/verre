import { writeFileSync } from 'node:fs'

// The package root declares "type": "module", which applies to every .js file
// in the package. The CommonJS build under build/cjs/ must override that so Node
// interprets those files as CommonJS instead of ESM.
writeFileSync(
  new URL('../build/cjs/package.json', import.meta.url),
  JSON.stringify({ type: 'commonjs' }) + '\n',
)
