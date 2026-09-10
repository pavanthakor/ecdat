// A Node cipher suite selected through a variable. The suite string carries
// the algorithm, key size and mode in one token, so missing it loses all
// three.
import * as crypto from "crypto";

const CONFIGURED_SUITE = "aes-256-gcm";

export function encrypt(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  const suite = "aes-128-cbc";
  const cipher = crypto.createCipheriv(suite, key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

export function encryptAead(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  const cipher = crypto.createCipheriv(CONFIGURED_SUITE, key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}
