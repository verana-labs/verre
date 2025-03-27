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
npm install verre
```
or
```bash
yarn add verre
```

## Overview
The `resolve` method is used to resolve a Decentralized Identifier (DID), validate its associated document, and verify any linked services. This function retrieves the DID document, processes its verifiable credentials, and determines its trust status.

## Importing the Method
```typescript
import { resolve } from 'verre';
```

## Method Signature
```typescript
async function resolve(did: string, options?: ResolverConfig): Promise<TrustedResolution>
```

## Parameters
- `did` (**string**, required): The Decentralized Identifier (DID) to resolve.
- `options` (**ResolverConfig**, optional): Configuration options for the resolver, including the trust registry URL.
  - `trustRegistryUrl` (string, optional): The URL of the trust registry used for DID resolution

## Return Value
Returns a `Promise<TrustedResolution>` that resolves to an object containing:

- `resolvedDidDocument` (**ResolvedDidDocument**, optional): The resolved DID document.
- `metadata` (**TrustedResolutionMetadata**, required): Metadata related to the resolution, including possible states and error codes.
  - `content`
  - `status`
  - `errorCode`
- `verifiableService` (**Record<string, string>**, optional): The entity that provided the credential.
- `issuerCredential` (**Record<string, string>**, optional): A record indicating the approved issuer.
- `type` (**ECS**, optional): The type of resolved entity, representing essential credentials.

## Usage Example
```typescript
(async () => {
  try {
    const did = 'did:example:123456';
    const options = { trustRegistryUrl: 'https://trust-registry.example.com' };
    
    const resolution = await resolve(did, options);
    
    console.log('Resolved DID Document:', resolution.resolvedDidDocument);
    console.log('Trust Metadata:', resolution.metadata);
  } catch (error) {
    console.error('Error resolving DID:', error);
  }
})();
```

## Notes
- The method supports ECS (Entity Credential Schema) identifiers such as `ORG`, `PERSON`, `USAR-AGENT`, and `SERVICE`.
- The function exits early if both `issuerCredential` and `verifiableService` are found during credential processing.

This method is essential for resolving and validating DIDs in a trusted ecosystem.

