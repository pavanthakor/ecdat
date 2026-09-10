// must_fire: js-hardcoded-key (ADR-0034), on TypeScript. The Angular-service
// shape of the Juice Shop false positives -- a `private readonly` class field
// -- but this field DOES reach a key parameter, so it is key material and must
// still fire. The sentinel must reach no Finding.
import * as crypto from 'crypto'

export class RequestSigningService {
  private readonly signingKey = 'TSSINKSENTINELclassFieldHmacKey1'

  sign (payload: string): string {
    return crypto.createHmac('sha256', this.signingKey).update(payload).digest('hex')
  }
}
