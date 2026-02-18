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

The Verre resolver provides two primary resolution methods:

* **`resolveDID`**: Resolves a Decentralized Identifier (DID), retrieves its DID Document, validates its services, and performs trust evaluation using configured registries.
* **`resolveCredential`**: Validates a W3C Verifiable Credential by extracting its issuer and evaluating it against trust registries.

Both methods return an object describing the trust evaluation outcome.

### Import

```ts
import { resolveDID, resolveCredential, verifyIssuerPermissions } from '@verana-labs/verre';
```

## Method Signatures

```ts
async function resolveDID(did: string, options?: ResolverConfig): Promise<TrustResolution>
async function resolveCredential(credential: W3cVerifiableCredential, options?: ResolverConfig): Promise<TrustResolution>
async function verifyIssuerPermissions(options: VerifyIssuerPermissionsOptions): Promise<{ verified: boolean }>
```

## Parameters

### Common (`options` shared across methods)

* **verifiablePublicRegistries** (*VerifiablePublicRegistry[]*): Trusted registry definitions for validation.
* **didResolver** (*Resolver*, optional): Custom universal resolver instance.
* **agentContext** (*AgentContext*, required): Global runtime context for Credo-TS agents.
* **cached** (*boolean*, optional): Indicates whether credential verification should be performed or if a previously validated result can be reused.
* **skipDigestSRICheck** (*boolean*, optional): Indicates whether to verify the integrity (digestSRI) of the credentials

---

## Method Details

### resolveDID

#### Parameters

* **did** (*string*, required): DID to resolve.
* **options** (*ResolverConfig*): Resolver configuration.

#### Return Value

Resolves to a `TrustResolution` containing:

* **didDocument** (*DIDDocument*, optional): Resolved DID Document.
* **verified** (*boolean*): Whether the DID and its services passed trust checks.
* **outcome** (*TrustResolutionOutcome*): Final trust evaluation status.
* **metadata** (*TrustResolutionMetadata*, optional): Error or diagnostic information.
* **service** (*IService*, optional): Verified DID service.
* **serviceProvider** (*ICredential*, optional): Credential representing the trust provider.

---

### resolveCredential

#### Parameters

* **credential** (*W3cVerifiableCredential*, required): Credential to resolve.
* **options** (*ResolverConfig*): Resolver configuration.

#### Return Value

Resolves to a `TrustResolution` containing:

* **issuer** (*string*): Identifier of the credential issuer.
* **verified** (*boolean*): Whether the issuer passed trust validation.
* **outcome** (*TrustResolutionOutcome*): Final trust evaluation status.

---

### verifyIssuerPermissions

#### Parameters

* **issuer** (*string | { id?: string }*): Issuer claiming permission to issue the credential.
* **jsonSchemaCredentialId** (*string*): URL or reference to the JSON schema defining the credential structure.
* **issuanceDate** (*string*): Date when the credential was issued.
* **verifiablePublicRegistries** (*VerifiablePublicRegistry[]*): Trusted registries used to validate permission rules.


---

### Usage Example

```typescript
import { resolve } from '@verana-labs/verre';

(async () => {
  const did = 'did:example:123456';
  const verifiablePublicRegistries = [
    {
      name: 'vpr:hostname:main',
      baseurls: ['http://testTrust.com'],
      production: true,
    },
  ];

  const resolution = await resolveDID(did, { verifiablePublicRegistries, agentContext });
  console.log('Resolved DID Document:', resolution.resolvedDidDocument);
  console.log('Trust Metadata:', resolution.metadata);
})();
```

### Using Credo-TS with a Default DID Resolver

```ts
import { Resolver } from 'did-resolver'
import { AgentContext } from '@credo-ts/core'

// Set up the agent
const agent = await setupAgent({ name: 'Default DID Resolver Test with Credo' })
const agentContext = agent.dependencyManager.resolve(AgentContext)

// By default, if no resolver is provided, the Credo-TS resolver will be used
await resolveDID('did:web:example.com', {
  trustRegistryUrl: 'https://registry.example.com',
  agentContext,
})
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
  },
];

// Use the custom resolver in the call to `resolve`
await resolveDID('did:web:example.com', {
  verifiablePublicRegistries,
  didResolver,
  agentContext,
})
```

### Example: Agent with In-Memory Askar Wallet and DID Resolver (Generic)

```ts
import { Agent, AgentContext, InitConfig } from '@credo-ts/core'
import { AskarModule } from '@credo-ts/askar'
import { agentDependencies } from '@credo-ts/node'
import { ariesAskar } from '@hyperledger/aries-askar-nodejs'
import { Resolver } from 'did-resolver'
import * as didWeb from 'web-did-resolver'

import { getAskarStoreConfig } from '../src/helpers'

// Create the in-memory wallet config
const walletConfig = getAskarStoreConfig('InMemoryTestAgent', { inMemory: true })
const didResolver = new Resolver(didWeb.getResolver())

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
const agentContext = agent.dependencyManager.resolve(didResolver, AgentContext)

// Example usage of the DID Resolver
const result = await resolveDID('did:web:example.com', {
  agentContext,
})
console.log('Resolved DID Document:', result)
```

## Notes
- The method supports ECS (Entity Credential Schema) identifiers such as `ORG`, `PERSON`, `USER-AGENT`, and `SERVICE`.
- The function exits early if both `issuerCredential` and `verifiableService` are found during credential processing.

This method is essential for resolving and validating DIDs in a trusted ecosystem.

