import { X25519_V1 } from './X25519_v1'
import { CREDENTIALS_V1 } from './credentials_v1'
import { DID_V1 } from './did_v1'
import { ED25519_V1 } from './ed25519_v1'
import { SECURITY_V1 } from './security_v1'
import { SECURITY_V2 } from './security_v2'

export const DEFAULT_CONTEXTS = {
  'https://w3id.org/security/v1': SECURITY_V1,
  'https://w3id.org/security/v2': SECURITY_V2,
  'https://w3id.org/security/suites/x25519-2019/v1': X25519_V1,
  'https://w3id.org/security/suites/ed25519-2018/v1': ED25519_V1,
  'https://www.w3.org/2018/credentials/v1': CREDENTIALS_V1,
  'https://w3id.org/did/v1': DID_V1,
  'https://www.w3.org/ns/did/v1': DID_V1,
  'https://w3.org/ns/did/v1': DID_V1,
}
