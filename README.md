# Verana Trust Resolver (VerRe)

The **Verana Trust Resolver** library provides a set of functions to resolve Decentralized Identifiers (DIDs), validate their associated documents, process Verifiable Credentials, and check their trust status according to the [**Verifiable Trust** specifications](https://verana-labs.github.io/verifiable-trust-spec/#vt-json-schema-cred-verifiable-trust-json-schema-credential) of the Verana blockchain.

The main entry point for using the resolver is the `resolve` function, which allows users to retrieve and validate a DID document, process its credentials, and check its trust status against the **Verana Trust Registry**.

---

## Compatibility Note

### Verifiable Trust spec versions

| Verifiable Trust spec | verre |
| --------------------- | ----- |
| v3 (current testnet)  | 0.3.x |
| v4 onwards            | 0.4.x |

verre 0.4.x identifies Essential Credential Schemas by the v4 reference digests ([ECS-EC](https://verana-labs.github.io/verifiable-trust-spec/versions/v4/#ecs-ec-essential-credential-schemas-ecosystem)), so v3 schemas are reported as unknown. Legacy deployments should stay on 0.3.x.

### didwebvh-ts

`didwebvh-ts@2.7.2` is only supported up to **verre v0.2.6**.
From `2.7.3`, the library enforces spec-compliant validation, which may break resolution for older (non-compliant) DID logs.

If you are using newer versions of verre with legacy DIDs, you may encounter issues or need a temporary patch until your DIDs are re-issued.

This change is due to versions prior to `2.7.3` not fully complying with the spec.
See: [https://github.com/verana-labs/verre/issues/103](https://github.com/verana-labs/verre/issues/103)

---

## **Table of Contents**
1. [Getting Started](#getting-started)
1. [Overview](#overview)
1. [Importing the Method](#importing-the-method)
1. [Method Signature](#method-signature)
1. [Parameters](#parameters)
1. [Return Value](#return-value)
1. [Usage Example](#usage-example)
1. [Registry Adapter — embedded use](#registry-adapter--embedded-use)
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
import { resolveDID, resolveCredential, verifyParticipant } from '@verana-labs/verre';
```

## Method Signatures

```ts
async function resolveDID(did: string, options?: ResolverConfig): Promise<TrustResolution>
async function resolveCredential(credential: W3cVerifiableCredential, options?: ResolverConfig): Promise<TrustResolution>
async function verifyParticipant(options: VerifyParticipantOptions): Promise<{ verified: boolean }>
```

## Parameters

### Common (`options` shared across methods)

* **verifiablePublicRegistries** (*VerifiablePublicRegistry[]*): Trusted registry definitions for validation.
* **didResolver** (*Resolver*, optional): Custom universal resolver instance.
* **cache** (*TrustResolutionCache<string, Promise<TrustResolution>*, optional): Cache store for trust resolution results. When provided, a successful resolution is stored keyed by DID and returned directly on subsequent calls. Any object implementing the `TrustResolutionCache` interface is accepted, the library provides `InMemoryCache` as a built-in implementation.
* **skipDigestSRICheck** (*boolean*, optional): When true, skips verification of the credential integrity (digestSRI). Defaults to false.
* **ecsEcosystems** (*EcsEcosystem[]*, optional): Ecosystems whitelisted to create Essential Credential Schemas per [WL-ECS] (`{ did, vpr }` pairs, where `vpr` matches a `verifiablePublicRegistries[].scheme`). When set, a schema whose Ecosystem is not whitelisted degrades to a regular VTC. When undefined, any Ecosystem is accepted. Requires a registry adapter; verre throws if one is not configured. Resolutions are cached per whitelist.
* **logger** (*IVerreLogger*, optional): Logger instance for the resolution process. Accepts any object that implements the `IVerreLogger` interface.

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

### verifyParticipant

#### Parameters

* **did** (*string*): The DID of the entity to validate as a Participant.
* **jsonSchemaCredentialId** (*string*): URL or reference to the JSON schema defining the credential structure.
* **issuanceDate** (*string*): Date when the credential was issued.
* **verifiablePublicRegistries** (*VerifiablePublicRegistry[]*): Trusted registries used to validate Participant entries.
* **role** (*ParticipantRole*): The Participant role to verify.
* **logger** (*IVerreLogger*, optional): Logger used for debugging


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

## Registry Adapter — embedded use

By default, verre resolves Participants and schemas by making HTTP calls to the registry's
API and indexer endpoints. This works well when verre is used as an external client.

However, if your service **is itself the registry** (e.g. a trust-registry backend or
indexer that also needs to validate incoming DIDs or credentials), those HTTP calls would
loop back into the same process — adding unnecessary network latency and a dependency on
the network stack.

For this case, each `VerifiablePublicRegistry` entry accepts an optional `adapter` field
that implements `IRegistryAdapter`. When verre encounters a credential referencing that
registry, it calls the adapter's methods directly instead of making any HTTP request.

### Interface

```ts
interface IRegistryAdapter {
  // Returns the raw JSON text of the subject schema by its resolved URL.
  fetchSchema(url: string): Promise<string>

  // Returns the Participant record for a DID, or undefined if none exists.
  // verre handles date-range validation (effective_from / effective_until) after this call.
  fetchParticipant(
    schemaId: string,
    did: string,
    role: ParticipantRole,
  ): Promise<
    Pick<Participant, 'role' | 'created' | 'effective_from' | 'effective_until'> | undefined
  >

  // Returns the DID of the Ecosystem that created a schema, for the [WL-ECS] whitelist.
  fetchSchemaEcosystemDid(schemaId: string): Promise<string | undefined>
}
```

### Example

```ts
import { resolveDID, IRegistryAdapter, VerifiablePublicRegistry, ParticipantRole } from '@verana-labs/verre'

class RegistryAdapter implements IRegistryAdapter {
  constructor(
    private schemaService: SchemaService,
    private participantService: ParticipantService,
  ) {}

  async fetchSchema(url: string): Promise<string> {
    // Direct in-process lookup — no HTTP
    return this.schemaService.getJsonByUrl(url)
  }

  async fetchParticipant(schemaId: string, did: string, role: ParticipantRole) {
    // Direct in-process lookup — no HTTP
    return this.participantService.findFirst({ schemaId, did, role })
  }

  async fetchSchemaEcosystemDid(schemaId: string) {
    return this.schemaService.getEcosystemDid(schemaId)
  }
}

const registries: VerifiablePublicRegistry[] = [
  {
    id: 'vna-mainnet-1',
    scheme: 'vpr:verana:vna-mainnet-1',
    api: ['https://idx.mainnet.verana.network'],
    production: true,
    adapter: new RegistryAdapter(schemaService, participantService),
  },
]

const result = await resolveDID(did, { verifiablePublicRegistries: registries })
```

When `adapter` is omitted, verre falls back to standard HTTP resolution as usual.

---

## Notes
- The method supports ECS (Entity Credential Schema) identifiers such as `ORG`, `PERSONA`, `USER-AGENT`, `SERVICE`, and `BADGE`.
- The function exits early if both `issuerCredential` and `verifiableService` are found during credential processing.

This method is essential for resolving and validating DIDs in a trusted ecosystem.

