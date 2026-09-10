#!/usr/bin/env bash
# Rebuild the committed binary fixtures. NOT run by the test suite.
#
# The binaries in this directory are COMMITTED on purpose (ADR-0025): a scanner
# test that compiled its own fixtures would depend on a toolchain, an OpenSSL
# version and a linker, and would then be measuring those rather than the
# scanner. Committed bytes make the answer key exact and the suite hermetic.
#
# This script records how they were made, so a reviewer can reproduce them and
# a maintainer can regenerate them when a technique changes.
#
# Requires: gcc, strip, python3. NOT required at test time.
set -euo pipefail
cd "$(dirname "$0")"

# ---------------------------------------------------------------------------
# 1. An ELF importing known libcrypto symbols.
#
# The OpenSSL headers are not installed on the build host, so the source
# declares the entry points itself -- the symbol NAMES are all the linker and
# the scanner need. Linked against the runtime soname directly (`-l:`) because
# the `libcrypto.so` development symlink needs the -dev package.
# ---------------------------------------------------------------------------
cat > /tmp/ecdat_crypto_app.c <<'EOF'
#include <stdio.h>
extern void *EVP_MD_CTX_new(void);
extern int EVP_DigestInit_ex(void *, const void *, void *);
extern const void *EVP_sha256(void);
extern const void *EVP_aes_256_gcm(void);
extern void *RSA_new(void);
extern int RSA_sign(int, const unsigned char *, unsigned int,
                    unsigned char *, unsigned int *, void *);
extern void *EC_KEY_new_by_curve_name(int);
extern int PKCS5_PBKDF2_HMAC(const char *, int, const unsigned char *, int,
                             int, const void *, int, unsigned char *);
int main(void) {
    void *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), 0);
    (void)EVP_aes_256_gcm();
    (void)RSA_new();
    (void)EC_KEY_new_by_curve_name(415);
    unsigned char sig[512]; unsigned int len = 0;
    RSA_sign(672, (const unsigned char *)"x", 1, sig, &len, 0);
    PKCS5_PBKDF2_HMAC("p", 1, (const unsigned char *)"s", 1, 1000, 0, 32, sig);
    printf("%p\n", ctx);
    return 0;
}
EOF
gcc -O0 -o elf_openssl_symbols /tmp/ecdat_crypto_app.c -l:libcrypto.so.3

# 2. A STRIPPED copy of the same binary. The dynamic symbol table survives
#    `strip` -- that is the point: it shows what stripping does and does not
#    cost, which is the honest coverage report.
cp elf_openssl_symbols elf_openssl_symbols_stripped
strip --strip-all elf_openssl_symbols_stripped

# 3. A trivial non-crypto ELF: the PRECISION decoy. libc imports alone are not
#    cryptography.
cat > /tmp/ecdat_hello.c <<'EOF'
#include <stdio.h>
#include <string.h>
int main(void) {
    char buf[64];
    strcpy(buf, "hello, world");
    printf("%s (%zu)\n", buf, strlen(buf));
    return 0;
}
EOF
gcc -O0 -o elf_hello /tmp/ecdat_hello.c

# 4-7. Byte-technique fixtures: PEM, OID, constants, version banner. Written by
#      the Python helper below so the exact bytes are reproducible.
python3 make_payloads.py

echo "fixtures rebuilt:"
ls -la elf_* pe_* broken.bin 2>/dev/null
