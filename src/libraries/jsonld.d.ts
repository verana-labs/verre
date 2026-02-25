declare module '@digitalcredentials/jsonld' {
  interface CanonizeOptions {
    algorithm?: string
    format?: string
    safe?: boolean
    documentLoader?: (url: string) => Promise<DocumentLoaderResult>
  }

  interface DocumentLoaderResult {
    contextUrl: string | null
    documentUrl: string
    document: Record<string, unknown>
  }

  export type DocumentLoader = (url: string) => Promise<DocumentLoaderResult>

  const jsonld: {
    canonize(input: unknown, options?: CanonizeOptions): Promise<string>
    expand(input: unknown, options?: Record<string, unknown>): Promise<unknown[]>
    compact(input: unknown, context: unknown, options?: Record<string, unknown>): Promise<unknown>
    frame(input: unknown, frame: unknown, options?: Record<string, unknown>): Promise<unknown>
    documentLoaders: {
      node: () => (url: string) => Promise<unknown>
    }
  }

  export default jsonld
}
