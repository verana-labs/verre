import { DidResolverService } from '@credo-ts/core'
import { Resolver } from 'did-resolver'
import Redis from 'ioredis'
import { GenericContainer, StartedTestContainer } from 'testcontainers'
import { describe, it, beforeAll, afterAll, vi, expect } from 'vitest'

import { resolveDID, TrustResolutionOutcome } from '../../src'
import {
  buildV4Fixtures,
  fetchMocker,
  getCredoTsDidResolver,
  setupAgent as setupAndInitializeAgent,
  TrustResolutionRedisCache,
  v4TestDocumentLoader,
  verifiablePublicRegistries,
  V4Fixtures,
} from '../__mocks__'

describe('TrustResolutionRedisCache with Redis (testcontainers)', () => {
  let container: StartedTestContainer
  let redis: Redis
  let didResolver: ReturnType<typeof getCredoTsDidResolver>
  let fixtures: V4Fixtures

  beforeAll(async () => {
    container = await new GenericContainer('redis:7-alpine').withExposedPorts(6379).start()

    redis = new Redis({
      host: container.getHost(),
      port: container.getMappedPort(6379),
    })

    const agent = await setupAndInitializeAgent({
      name: 'CacheTestAgent',
      documentLoader: v4TestDocumentLoader,
    })
    didResolver = getCredoTsDidResolver(agent.context)
    fixtures = await buildV4Fixtures(agent)

    vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async () => ({
      didResolutionMetadata: {},
      didDocumentMetadata: {},
      didDocument: fixtures.didDocument,
    }))

    vi.spyOn(DidResolverService.prototype, 'resolve').mockImplementation(async () => ({
      didResolutionMetadata: {},
      didDocumentMetadata: {},
      didDocument: fixtures.credoDidDocument,
    }))

    fetchMocker.enable()
  }, 60_000)

  afterAll(async () => {
    fetchMocker.reset()
    fetchMocker.disable()
    vi.clearAllMocks()
    await redis.quit()
    await container.stop()
  })

  it('should store TrustResolution in Redis and serve the second call from cache', async () => {
    const did = fixtures.did
    fetchMocker.setMockResponses(fixtures.mockResponses)

    // First call: full resolution
    const store = new TrustResolutionRedisCache(redis)

    const result = await resolveDID(did, {
      verifiablePublicRegistries,
      didResolver,
      cache: store,
    })

    expect(result.verified).toBe(true)
    expect(result.outcome).toBe(TrustResolutionOutcome.VERIFIED_TEST)

    await new Promise(r => setTimeout(r, 100))

    const redisRaw = await redis.get(did)
    expect(redisRaw).not.toBeNull()
    const persisted = JSON.parse(redisRaw!)
    expect(persisted.verified).toBe(true)

    const store2 = new TrustResolutionRedisCache(redis)
    await store2.preload(did)

    fetchMocker.reset()
    fetchMocker.enable()

    const fetchCountBefore = (global.fetch as any).mock.calls.length

    // Second call: cached resolution
    const cachedResult = await resolveDID(did, {
      verifiablePublicRegistries,
      cache: store2,
    })

    expect(cachedResult.verified).toBe(true)
    expect(cachedResult.outcome).toBe(TrustResolutionOutcome.VERIFIED_TEST)
    expect((global.fetch as any).mock.calls.length).toBe(fetchCountBefore)
  }, 30_000)
})
