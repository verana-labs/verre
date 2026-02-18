import { describe, it, expect } from 'vitest'

import { verifyDigestSRI } from '../../src/utils/verifier'

describe('verifyDigestSRI', () => {
  const testData = {
    name: 'Test Schema',
    schema: { type: 'object', properties: { id: { type: 'string' } } },
  }

  it('should skip validation when verifyIntegrity is false', () => {
    const schemaJson = JSON.stringify(testData.schema)
    const invalidDigestSRI = 'sha256-invalid_hash_value_here'

    expect(() => {
      verifyDigestSRI(schemaJson, invalidDigestSRI, testData.name, false)
    }).not.toThrow()
  })
})
