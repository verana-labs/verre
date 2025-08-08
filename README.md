# Verana Trust Resolver (VerRe)

The **Verana Trust Resolver** library provides a set of functions to resolve Decentralized Identifiers (DIDs), validate their associated documents, process Verifiable Credentials, and check their trust status according to the [**Verifiable Trust** specifications](https://verana-labs.github.io/verifiable-trust-spec/#vt-json-schema-cred-verifiable-trust-json-schema-credential) of the Verana blockchain.

The main entry point for using the resolver is the `resolve` function, which allows users to retrieve and validate a DID document, process its credentials, and check its trust status against the **Verana Trust Registry**.

---

## **Table of Contents**
1. [Getting Started](#getting-started)
1. [Overview](#overview)
1. [Importing the Method](#importing-the-method)
1. [Method Signature](#method-signature)
1. [Parameters](#parameters)
1. [Return Value](#return-value)
1. [Usage Example](#usage-example)
1. [Notes](#notes)

---

## **Getting Started**

To use the Verana Trust Resolver, install the library and import the necessary modules:

```bash
npm install @verana-labs/verre
```
or
```bash
yarn add @verana-labs/verre
```

## Overview
The `resolve` method is used to resolve a Decentralized Identifier (DID), validate its associated document, and verify any linked services. This function retrieves the DID document, processes its verifiable credentials, and determines its trust status.

## Importing the Method
```typescript
import { resolve } from '@verana-labs/verre';
```

## Method Signature
```typescript
async function resolve(did: string, options?: ResolverConfig): Promise<TrustResolution>
```

## Parameters

- `did` (**string**, required): The Decentralized Identifier to resolve.
- `options` (**ResolverConfig**): Configuration options for the resolver.
  - `verifiablePublicRegistries` (**VerifiablePublicRegistry[]**): List of verifiable public registry definitions for validation.
  - `didResolver` (**Resolver**, optional): A custom [universal resolver](https://github.com/decentralized-identity/did-resolver) instance. Useful when integrating with specific resolution strategies, such as those from Credo-TS.
  - `agentContext` (**AgentContext**, mandatory): holds the global operational context of the agent, including its current runtime state, registered services, modules, dids, wallets, storage, and configuration from Credo-TS
> **Note:** This function internally uses additional fields (like `attrs`) for recursion and processing, which are not part of the public configuration interface.

## Return Value
Returns a `Promise<TrustResolution>` that resolves to an object containing:

* `didDocument` (*DIDDocument* | optional): The resolved DID Document.
* `verified` (*boolean*): Indicates whether the DID and its services passed trust validation.
* `outcome` (*TrustResolutionOutcome*): The result status of the trust resolution process.
* `metadata` (*TrustResolutionMetadata* | optional): Additional resolution metadata such as `errorMessage` or `errorCode`.
* `service` (*IService* | optional): The verified credential service offered by the resolved entity.
* `serviceProvider` (*ICredential* | optional): The credential representing the issuer or trust provider for the service.

## Usage Example

```typescript
import { resolve } from '@verana-labs/verre';

(async () => {
  const did = 'did:example:123456';
  const verifiablePublicRegistries = [
    {
      name: 'https://vpr-hostname/vpr',
      baseurls: ['http://testTrust.com'],
      production: true,
      version: '1.0',
    },
  ];

  const resolution = await resolve(did, { verifiablePublicRegistries, agentContext });
  console.log('Resolved DID Document:', resolution.resolvedDidDocument);
  console.log('Trust Metadata:', resolution.metadata);
})();
```

### Using Credo-TS to Provide a Custom DID Resolver

```ts
import { Resolver } from 'did-resolver'
import { DidResolverService, AgentContext } from '@credo-ts/core'

// Set up the agent
const agent = await setupAgent({ name: 'DID Service Test' })
const didResolverService = agent.dependencyManager.resolve(DidResolverService)
const agentContext = agent.dependencyManager.resolve(AgentContext)

// Create a custom resolver using Credo-TS resolution strategies
const didResolver = new Resolver({
  web: async (did: string) => didResolverService.resolve(agentContext, did),
  key: async (did: string) => didResolverService.resolve(agentContext, did),
  peer: async (did: string) => didResolverService.resolve(agentContext, did),
  jwk: async (did: string) => didResolverService.resolve(agentContext, did),
})
const verifiablePublicRegistries = [
  {
    name: 'https://vpr-hostname/vpr',
    baseurls: ['http://testTrust.com'],
    production: true,
    version: '1.0',
  },
];

// Use the custom resolver in the call to `resolve`
await resolve('did:web:example.com', {
  verifiablePublicRegistries,
  didResolver,
  agentContext,
})
```

### ✅ Example: Agent with In-Memory Askar Wallet and DID Resolver (Credo-TS)

```ts
import { Agent, AgentContext, DidResolverService, InitConfig } from '@credo-ts/core'
import { AskarModule } from '@credo-ts/askar'
import { agentDependencies } from '@credo-ts/node'
import { ariesAskar } from '@hyperledger/aries-askar-nodejs'
import { Resolver } from 'did-resolver'

import { getAskarStoreConfig } from '../src/helpers'

// Create the in-memory wallet config
const walletConfig = getAskarStoreConfig('InMemoryTestAgent', { inMemory: true })

// Agent initialization config
const config: InitConfig = {
  label: 'InMemoryTestAgent',
  walletConfig,
}

// Create and initialize the agent
const agent = new Agent({
  config,
  dependencies: agentDependencies,
  modules: {
    askar: new AskarModule({ ariesAskar }),
  },
})

await agent.initialize()

// Resolve dependencies
const agentContext = agent.dependencyManager.resolve(AgentContext)
const didResolverService = agent.dependencyManager.resolve(DidResolverService)

// Set up DID Resolver using Credo-TS resolution strategies
const didResolver = new Resolver({
  web: async (did) => didResolverService.resolve(agentContext, did),
})

// Example usage of the DID Resolver
const result = await resolve('did:web:example.com', {
  didResolver,
  agentContext,
})
console.log('Resolved DID Document:', result)
```

## Notes
- The method supports ECS (Entity Credential Schema) identifiers such as `ORG`, `PERSON`, `USER-AGENT`, and `SERVICE`.
- The function exits early if both `issuerCredential` and `verifiableService` are found during credential processing.

This method is essential for resolving and validating DIDs in a trusted ecosystem.

