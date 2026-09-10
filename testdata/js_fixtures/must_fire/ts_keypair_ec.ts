import * as crypto from "crypto";

// TypeScript again, and an EC keypair: Shor-broken, curve captured.
export function newSigningKey(cb: (e: Error | null) => void): void {
  crypto.generateKeyPair("ec", { namedCurve: "P-256" }, cb);
}
