// The same auth-bypass close in TypeScript, so `.ts` is proven on the
// propagated path and not only on the literal one.
import * as jwt from "jsonwebtoken";

export function issueUnsigned(claims: object): string {
  const alg = "none";
  return jwt.sign(claims, "", { algorithm: alg });
}

export function encryptSuite(): string {
  const suite = "aes-128-cbc";
  return suite;
}
