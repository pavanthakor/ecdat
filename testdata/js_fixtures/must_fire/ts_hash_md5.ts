import * as crypto from "crypto";

// A TypeScript file, to prove .ts is scanned and not only .js.
export function fingerprint(data: string): string {
  return crypto.createHash("md5").update(data).digest("hex");
}
