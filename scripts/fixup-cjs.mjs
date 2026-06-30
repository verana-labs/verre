import { writeFileSync } from 'node:fs'

// The package root declares "type": "module", which applies to every .js file in the package.
writeFileSync(
  new URL('../build/cjs/package.json', import.meta.url),
  JSON.stringify({ type: 'commonjs' }) + '\n',
)
