// FIXME: Imports order once https://github.com/openwallet-foundation/askar-wrapper-javascript/issues/77
// is solved
// eslint-disable-next-line prettier/prettier, import/order
import { askar, KdfMethod } from '@openwallet-foundation/askar-nodejs'

import { AskarModule, AskarModuleConfigStoreOptions } from '@credo-ts/askar'
import { Agent, DidsModule, utils, WebDidResolver } from '@credo-ts/core'
import { agentDependencies } from '@credo-ts/node'
import { WebVhDidResolver } from '@credo-ts/webvh'

export const setupAgent = async ({ name }: { name: string }) => {
  const agent = new Agent({
    dependencies: agentDependencies,
    modules: {
      askar: new AskarModule({
        askar,
        store: getAskarStoreConfig(name),
      }),
      dids: new DidsModule({
        resolvers: [new WebDidResolver(), new WebVhDidResolver()],
      }),
    },
  })

  await agent.initialize()
  return agent
}

/**
 * Generates a basic configuration object for initializing an Askar wallet store,
 * typically used with the Credo-TS `AskarModule`.
 *
 * This helper is intended for simple test or development wallets and supports
 * in-memory SQLite configuration by default.
 *
 * @param name - The base name for the wallet. Used as part of the wallet ID.
 * @param options - Optional configuration overrides.
 * @param options.inMemory - If true (default), the SQLite database will be in-memory.
 * @param options.random - Optional random string to append to the wallet ID. Defaults to a short UUID segment.
 * @param options.maxConnections - Optional maximum number of connections for the SQLite database.
 *
 * @returns A wallet configuration object compatible with `AskarModuleConfigStoreOptions`.
 *
 * @example
 * ```ts
 * const walletConfig = getAskarStoreConfig('MyAgent', { inMemory: true });
 * const agent = new Agent({
 *   config: {
 *     label: 'MyAgent',
 *     walletConfig,
 *   },
 *   dependencies: agentDependencies,
 *   modules: {
 *     askar: new AskarModule({ ariesAskar }),
 *   },
 * });
 * ```
 */
export function getAskarStoreConfig(name: string): AskarModuleConfigStoreOptions {
  return {
    id: `Wallet: ${name} - ${utils.uuid().slice(0, 4)}`,
    key: 'DZ9hPqFWTPxemcGea72C1X1nusqk5wFNLq6QPjwXGqAa',
    keyDerivationMethod: KdfMethod.Raw,
  }
}
