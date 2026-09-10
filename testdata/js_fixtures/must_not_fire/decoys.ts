// TypeScript decoys, so TS handling is proven on the precision side too.

// A type whose name reads like crypto but declares no cryptography.
export interface CipherSuitePreference {
  readonly label: string;
  readonly md5Column: string;
}

// Prose naming algorithms: crypto.createHash("sha1"), createCipheriv("aes-128-cbc").
export const migrationNotes =
  "SHA-1 signing was retired; DES was never used in this service";

// A name-scoped RNG rule must not fire on a non-key use, in TS either.
export function pickBanner(banners: string[]): string {
  const index = Math.floor(Math.random() * banners.length);
  return banners[index];
}

export function describe(pref: CipherSuitePreference): string {
  return `${pref.label}:${pref.md5Column}:${migrationNotes}`;
}
