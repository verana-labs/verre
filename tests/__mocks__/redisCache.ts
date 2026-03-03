import Redis from 'ioredis'

import { CacheStore } from '../../src'

export class RedisCacheStore implements CacheStore<string, Promise<unknown>> {
  private local = new Map<string, Promise<unknown>>()

  constructor(private readonly redis: Redis) {}

  get(key: string): Promise<unknown> | undefined {
    return this.local.get(key)
  }

  set(key: string, value: Promise<unknown>): void {
    this.local.set(key, value)
    value.then(resolved => this.redis.set(key, JSON.stringify(resolved), 'EX', 300)).catch(() => {})
  }

  delete(key: string): void {
    this.local.delete(key)
    this.redis.del(key).catch(() => {})
  }

  clear(): void {
    this.local.clear()
    this.redis.flushall().catch(() => {})
  }

  async preload(key: string): Promise<void> {
    const raw = await this.redis.get(key)
    if (raw) this.local.set(key, Promise.resolve(JSON.parse(raw)))
  }
}
