export interface DereferencedVC {
  vcId: string
  vc: Record<string, unknown>
  format: 'w3c-jsonld' | 'w3c-jwt' | 'anoncreds'
  issuerDid: string
  credentialSchemaId?: string
  effectiveIssuanceTime?: string
  digestSRI?: string
  verified: boolean
  verificationError?: string
}
