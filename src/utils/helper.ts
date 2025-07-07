import { KeyDerivationMethod, utils } from '@credo-ts/core'

import { TrustResolutionMetadata, TrustErrorCode } from '../types'

import { TrustError } from './trustError'

/**
 * Builds metadata for a trust resolution process.
 *
 * If no error code is provided, the status is set to `RESOLVED`.
 * Otherwise, it is set to `ERROR`, including the error details.
 *
 * @param errorCode - Optional error code indicating a trust validation failure.
 * @param errorMessage - Optional descriptive error message.
 * @returns The metadata containing the resolution status and error details if applicable.
 */
export function buildMetadata(errorCode: TrustErrorCode, errorMessage: string): TrustResolutionMetadata {
  return {
    errorCode,
    errorMessage,
  }
}

/**
 * Fetches and returns JSON data from a given URL.
 *
 * Performs an HTTP request and attempts to parse the response as JSON.
 * If the request fails, it throws a `TrustError` with relevant details.
 *
 * @template T - The expected structure of the JSON response.
 * @param url - The URL to fetch the data from.
 * @returns A promise resolving to the parsed JSON data.
 * @throws {TrustError} If the HTTP request fails.
 */
export async function fetchJson<T = any>(url: string): Promise<T> {
  const response = await fetch(url)

  if (!response.ok) {
    throw new TrustError(
      TrustErrorCode.INVALID_REQUEST,
      `Failed to fetch data from ${url}: ${response.status} ${response.statusText}`,
    )
  }

  return response.json() as T
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
