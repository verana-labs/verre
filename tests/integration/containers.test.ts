import { DidDocument, DidResolverService } from '@credo-ts/core'
import { Resolver } from 'did-resolver'
import Redis from 'ioredis'
import { GenericContainer, StartedTestContainer } from 'testcontainers'
import { describe, it, beforeAll, afterAll, vi, expect } from 'vitest'

import { resolveDID, TrustResolutionOutcome } from '../../src'
import {
  fetchMocker,
  getCredoTsDidResolver,
  integrationDidDoc,
  integrationMockResponses,
  TrustResolutionRedisCache,
  setupAgent as setupAndInitializeAgent,
  verifiablePublicRegistries,
} from '../__mocks__'

const did = 'did:web:bcccdd780017.ngrok-free.app'

describe('TrustResolutionRedisCache with Redis (testcontainers)', () => {
  let container: StartedTestContainer
  let redis: Redis
  let didResolver: ReturnType<typeof getCredoTsDidResolver>

  beforeAll(async () => {
    container = await new GenericContainer('redis:7-alpine').withExposedPorts(6379).start()

    redis = new Redis({
      host: container.getHost(),
      port: container.getMappedPort(6379),
    })

    const agent = await setupAndInitializeAgent({ name: 'CacheTestAgent' })
    didResolver = getCredoTsDidResolver(agent.context)

    vi.spyOn(Resolver.prototype, 'resolve').mockImplementation(async () => ({
      didResolutionMetadata: {},
      didDocumentMetadata: {},
      didDocument: integrationDidDoc,
    }))

    vi.spyOn(DidResolverService.prototype, 'resolve').mockImplementation(async () => ({
      didResolutionMetadata: {},
      didDocumentMetadata: {},
      didDocument: new DidDocument({ ...integrationDidDoc, context: integrationDidDoc['@context'] }),
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

  it('does not persist unverified resolutions in Redis', async () => {
    fetchMocker.setMockResponses(integrationMockResponses)

    // v3 fixture content resolves unverified on 0.4.x; only verified results are cached
    const store = new TrustResolutionRedisCache(redis)

    const result = await resolveDID(did, {
      verifiablePublicRegistries,
      didResolver,
      cache: store,
    })

    expect(result.verified).toBe(false)
    expect(result.outcome).toBe(TrustResolutionOutcome.INVALID)

    await new Promise(r => setTimeout(r, 100))

    const redisRaw = await redis.get(did)
    expect(redisRaw).toBeNull()

    const store2 = new TrustResolutionRedisCache(redis)
    await store2.preload(did)

    const fetchCountBefore = (global.fetch as any).mock.calls.length

    // Nothing was cached, so the second call resolves again
    const cachedResult = await resolveDID(did, {
      verifiablePublicRegistries,
      cache: store2,
    })

    expect(cachedResult.verified).toBe(false)
    expect(cachedResult.outcome).toBe(TrustResolutionOutcome.INVALID)
    expect((global.fetch as any).mock.calls.length).toBeGreaterThan(fetchCountBefore)
  }, 30_000)
})
