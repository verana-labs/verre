import { describe, expect, it } from 'vitest'

import { LINKED_VP_FRAGMENT_PATTERNS } from '../../src/resolver/didValidator'

const matches = (fragment: string): boolean => LINKED_VP_FRAGMENT_PATTERNS.some(p => p.test(fragment))

describe('linked-VP fragment patterns', () => {
  it('matches the spec fragments ([VT-CRED-W3C-LINKED-VP], #vpr-schemas-*-vtc-vp)', () => {
    expect(matches('vpr-schemas-service-vtc-vp')).toBe(true)
    expect(matches('vpr-schemas-org-vtc-vp')).toBe(true)
    expect(matches('vpr-schemas-persona-vtc-vp')).toBe(true)
  })

  it('still matches the legacy -c-vp fragments', () => {
    expect(matches('vpr-schemas-service-c-vp')).toBe(true)
    expect(matches('vpr-ecs-service-c-vp')).toBe(true)
  })

  it('does not match unrelated fragments', () => {
    expect(matches('whois')).toBe(false)
    expect(matches('vpr-schemas-service-vtjsc-vp')).toBe(false)
    expect(matches('didcomm')).toBe(false)
  })
})
