import type { InitConfig } from '@credo-ts/core'

import { AskarModule } from '@credo-ts/askar'
import { Agent, HttpOutboundTransport, KeyDerivationMethod, utils, WsOutboundTransport } from '@credo-ts/core'
import { agentDependencies } from '@credo-ts/node'
import { askar } from '@openwallet-foundation/askar-nodejs'

export const setupAgent = async ({ name }: { name: string }) => {
  const agentConfig: InitConfig = {
    label: name,
    walletConfig: getAskarStoreConfig('InMemoryTestAgent', { inMemory: true }),
  }

  const agent = new Agent({
    config: agentConfig,
    dependencies: agentDependencies,
    modules: {
      askar: new AskarModule({
        ariesAskar: askar,
      }),
    },
  })

  agent.registerOutboundTransport(new HttpOutboundTransport())
  agent.registerOutboundTransport(new WsOutboundTransport())

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
export function getAskarStoreConfig(
  name: string,
  {
    inMemory = true,
    random = utils.uuid().slice(0, 4),
    maxConnections,
  }: { inMemory?: boolean; random?: string; maxConnections?: number } = {},
) {
  return {
    id: `Wallet: ${name} - ${random}`,
    key: 'DZ9hPqFWTPxemcGea72C1X1nusqk5wFNLq6QPjwXGqAa',
    keyDerivationMethod: KeyDerivationMethod.Raw,
    database: {
      type: 'sqlite',
      config: {
        inMemory,
        maxConnections,
      },
    },
  }
}
