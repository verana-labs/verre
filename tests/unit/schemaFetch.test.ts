import { createHash } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, MockInstance, vi } from 'vitest'

import { TrustErrorCode } from '../../src'
import { DEFAULT_SCHEMAS, JSON_SCHEMA_CREDENTIAL_V2 } from '../../src/libraries'
import { computeDigestSRI } from '../../src/utils/crypto'
import { clearSchemaCache, fetchSchemaCredential, fetchSchemaText, fetchText } from '../../src/utils/helper'
import { mockW3cJsonSchemaV2 } from '../__mocks__'

// The schema documents a credentialSchema pins: the W3C meta-schema is bundled, the others are
// fetched once and cached, and a transient failure is told apart from a final one.
const W3C_META_URL = 'https://www.w3.org/ns/credentials/json-schema/v2.json'
// the digestSRI that the Verifiable Trust JSON Schema Credentials pin for the W3C document
const W3C_META_DIGEST = 'sha384-FdPKzKLFNWo+3ZqV9vjuY8aNQk+636lvGRKKNzAfy93Q9jf+lNHD8j91g/KHWCBX'
const SCHEMA_URL = 'https://schemas.example/vt/cs/v1/js/ecs-service'

const sriOf = (text: string) => `sha256-${createHash('sha256').update(text).digest('base64')}`

const response = (status: number, body: string) =>
  ({
    ok: status >= 200 && status < 300,
    status,
    statusText: `status ${status}`,
    text: async () => body,
    json: async () => JSON.parse(body),
  }) as unknown as Response

describe('schema fetch', () => {
  let fetchSpy: MockInstance<typeof fetch>

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, 'fetch')
  })

  afterEach(() => {
    vi.restoreAllMocks()
    clearSchemaCache()
  })

  it('bundles the W3C meta-schema with the exact bytes that the pinned digest covers', () => {
    expect(DEFAULT_SCHEMAS[W3C_META_URL]).toBe(JSON_SCHEMA_CREDENTIAL_V2)
    expect(computeDigestSRI('sha384', JSON_SCHEMA_CREDENTIAL_V2)).toBe(W3C_META_DIGEST)
    expect(JSON.parse(JSON_SCHEMA_CREDENTIAL_V2).$id).toBe(
      'https://www.w3.org/2022/credentials/v2/json-schema-credential-schema.json',
    )
  })

  it('serves the bundled copy without network access when it matches the pinned digest', async () => {
    fetchSpy.mockResolvedValue(response(429, 'Too Many Requests'))

    await expect(fetchSchemaText(W3C_META_URL, W3C_META_DIGEST)).resolves.toBe(JSON_SCHEMA_CREDENTIAL_V2)
    // no pin means nothing to contradict the bundled copy
    await expect(fetchSchemaText(W3C_META_URL)).resolves.toBe(JSON_SCHEMA_CREDENTIAL_V2)

    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('fetches the document when the pinned digest differs from the bundled copy', async () => {
    const revised = JSON.stringify(mockW3cJsonSchemaV2)
    fetchSpy.mockResolvedValue(response(200, revised))

    await expect(fetchSchemaText(W3C_META_URL, sriOf(revised))).resolves.toBe(revised)

    expect(fetchSpy).toHaveBeenCalledWith(W3C_META_URL)
  })

  it('fetches a schema once and serves the cached copy afterwards', async () => {
    const body = '{"title":"ecs-service"}'
    fetchSpy.mockResolvedValue(response(200, body))

    await expect(fetchSchemaText(SCHEMA_URL, sriOf(body))).resolves.toBe(body)
    await expect(fetchSchemaText(SCHEMA_URL, sriOf(body))).resolves.toBe(body)

    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('shares one fetch between concurrent requests for one URL', async () => {
    const body = '{"title":"ecs-service"}'
    fetchSpy.mockImplementation(
      () => new Promise(resolve => setTimeout(() => resolve(response(200, body)), 10)),
    )

    const texts = await Promise.all([
      fetchSchemaText(SCHEMA_URL, sriOf(body)),
      fetchSchemaText(SCHEMA_URL, sriOf(body)),
      fetchSchemaText(SCHEMA_URL),
    ])

    expect(texts).toEqual([body, body, body])
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('does not cache a failed fetch', async () => {
    const body = '{"title":"ecs-service"}'
    fetchSpy
      .mockResolvedValueOnce(response(429, 'Too Many Requests'))
      .mockResolvedValueOnce(response(200, body))

    await expect(fetchSchemaText(SCHEMA_URL, sriOf(body))).rejects.toMatchObject({
      metadata: { errorCode: TrustErrorCode.UNAVAILABLE },
    })
    await expect(fetchSchemaText(SCHEMA_URL, sriOf(body))).resolves.toBe(body)

    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it('fetches again when the cached copy does not match the pinned digest', async () => {
    const v1 = '{"version":1}'
    const v2 = '{"version":2}'
    fetchSpy.mockResolvedValueOnce(response(200, v1)).mockResolvedValueOnce(response(200, v2))

    await expect(fetchSchemaText(SCHEMA_URL, sriOf(v1))).resolves.toBe(v1)
    await expect(fetchSchemaText(SCHEMA_URL, sriOf(v2))).resolves.toBe(v2)
    await expect(fetchSchemaText(SCHEMA_URL, sriOf(v2))).resolves.toBe(v2)

    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it('returns a copy that fails its pin for the caller to report', async () => {
    const body = '{"version":1}'
    fetchSpy.mockResolvedValue(response(200, body))

    // a cached copy that fails the pin is fetched again, in case the server has a newer one
    await expect(fetchSchemaText(SCHEMA_URL, 'sha256-AAAA')).resolves.toBe(body)
    await expect(fetchSchemaText(SCHEMA_URL, 'sha256-AAAA')).resolves.toBe(body)

    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it('keeps the newest copy cached when one pin fails it, for the callers whose pin matches', async () => {
    const body = '{"version":1}'
    fetchSpy.mockResolvedValue(response(200, body))

    await expect(fetchSchemaText(SCHEMA_URL, sriOf(body))).resolves.toBe(body)
    await expect(fetchSchemaText(SCHEMA_URL, 'sha256-AAAA')).resolves.toBe(body)
    // the stale pin of another credential did not evict the copy this one matches
    await expect(fetchSchemaText(SCHEMA_URL, sriOf(body))).resolves.toBe(body)

    expect(fetchSpy).toHaveBeenCalledTimes(2)
  })

  it('loads the document through the given loader and caches that copy', async () => {
    const body = '{"title":"ecs-service"}'
    const load = vi.fn(async () => body)

    await expect(fetchSchemaText(SCHEMA_URL, sriOf(body), load)).resolves.toBe(body)
    await expect(fetchSchemaText(SCHEMA_URL, sriOf(body), load)).resolves.toBe(body)

    expect(load).toHaveBeenCalledTimes(1)
    expect(load).toHaveBeenCalledWith(SCHEMA_URL)
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('does not cache a loader failure, and reports it as the loader raised it', async () => {
    const body = '{"title":"ecs-service"}'
    const failure = new Error('registry database is down')
    const load = vi
      .fn<(url: string) => Promise<string>>()
      .mockRejectedValueOnce(failure)
      .mockResolvedValueOnce(body)

    await expect(fetchSchemaText(SCHEMA_URL, sriOf(body), load)).rejects.toBe(failure)
    await expect(fetchSchemaText(SCHEMA_URL, sriOf(body), load)).resolves.toBe(body)

    expect(load).toHaveBeenCalledTimes(2)
  })

  describe('fetchSchemaCredential', () => {
    const CREDENTIAL_URL = 'https://ecs-trust-registry/service-credential-schema-credential.json'

    it('fetches a JSON Schema Credential once and serves the parsed cached copy afterwards', async () => {
      const credential = { id: CREDENTIAL_URL, type: ['VerifiableCredential', 'JsonSchemaCredential'] }
      fetchSpy.mockResolvedValue(response(200, JSON.stringify(credential)))

      await expect(fetchSchemaCredential(CREDENTIAL_URL)).resolves.toEqual(credential)
      await expect(fetchSchemaCredential(CREDENTIAL_URL)).resolves.toEqual(credential)

      expect(fetchSpy).toHaveBeenCalledTimes(1)
    })

    it('reports a rate-limited fetch as unavailable and does not cache it', async () => {
      fetchSpy
        .mockResolvedValueOnce(response(429, 'Too Many Requests'))
        .mockResolvedValueOnce(response(200, '{}'))

      await expect(fetchSchemaCredential(CREDENTIAL_URL)).rejects.toMatchObject({
        metadata: { errorCode: TrustErrorCode.UNAVAILABLE },
      })
      await expect(fetchSchemaCredential(CREDENTIAL_URL)).resolves.toEqual({})

      expect(fetchSpy).toHaveBeenCalledTimes(2)
    })
  })

  describe('fetchText', () => {
    it.each([
      [429, TrustErrorCode.UNAVAILABLE],
      [503, TrustErrorCode.UNAVAILABLE],
      [404, TrustErrorCode.INVALID_REQUEST],
      [400, TrustErrorCode.INVALID_REQUEST],
    ])('maps a %i status to the error code %s', async (status, errorCode) => {
      fetchSpy.mockResolvedValue(response(status, ''))

      await expect(fetchText(SCHEMA_URL)).rejects.toMatchObject({
        metadata: { errorCode, errorMessage: expect.stringContaining(`${status}`) },
      })
    })

    it('reports a network error as unavailable', async () => {
      fetchSpy.mockRejectedValue(new TypeError('fetch failed'))

      await expect(fetchText(SCHEMA_URL)).rejects.toMatchObject({
        metadata: {
          errorCode: TrustErrorCode.UNAVAILABLE,
          errorMessage: expect.stringContaining('fetch failed'),
        },
      })
    })
  })
})
