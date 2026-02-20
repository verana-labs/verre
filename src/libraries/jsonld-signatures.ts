import {
  constants as JsonLdConstants,
  purposes as JsonLdPurposes,
  suites as JsonLdSuites,
  verify as jsonLdVerify,
  // No type definitions available for this library
  //@ts-ignore
} from '@digitalcredentials/jsonld-signatures'

export interface Suites {
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  LinkedDataSignature: any
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  LinkedDataProof: any
}

export interface Purposes {
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
  AssertionProofPurpose: any
  AuthenticationProofPurpose: any
  ControllerProofPurpose: any
  ProofPurpose: any
}

// biome-ignore lint/suspicious/noExplicitAny: <explanation>
type Constants = any

export const suites = JsonLdSuites as Suites
export const purposes = JsonLdPurposes as Purposes
export const constants = JsonLdConstants as Constants

export interface VerifyOptions {
  document: any
  suite: any
  purpose: any
  documentLoader: (url: string) => Promise<any>
}

export interface VerifyResult {
  verified: boolean
  results: Array<{
    proof: any
    verified: boolean
    error?: Error
  }>
}

export const verify = async (options: VerifyOptions): Promise<VerifyResult> => {
  try {
    const { document, suite, purpose, documentLoader } = options
    const result = await jsonLdVerify(document, {
      suite,
      purpose,
      documentLoader,
    })
    return result as VerifyResult
  } catch (error) {
    return {
      verified: false,
      results: [
        {
          proof: null,
          verified: false,
          error: error instanceof Error ? error : new Error(String(error)),
        },
      ],
    }
  }
}
