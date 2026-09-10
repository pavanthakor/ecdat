import * as crypto from 'crypto'

export function legacyDigest (value: string): string {
  return crypto.createHash('md5').update(value).digest('hex')
}
