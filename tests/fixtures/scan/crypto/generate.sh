#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Regenerates the certificate and key fixtures. The output is committed, so tests never need
# the openssl command, and a fresh run only changes key material: the dates are fixed.
#
# Every key here is a test key made for this directory. None protects anything.
#
# Needs OpenSSL 3.4 or newer, for -not_before and -not_after.
#   tests/fixtures/scan/crypto/generate.sh [path/to/openssl]

set -eu

openssl=${1:-openssl}
cd "$(dirname "$0")"
rm -rf keys certs broken
mkdir keys certs broken

not_before=20260101000000Z
not_after=20310501120000Z
password=pass:pqscan-test

self_signed() { # key, digest, subject, extensions, output
    "$openssl" req -x509 -new -key "$1" "-$2" -subj "/CN=$3" -addext "$4" \
        -not_before "$not_before" -not_after "$not_after" -out "$5"
}

# Keys, in every container OpenSSL writes.
"$openssl" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/rsa-2048.key
"$openssl" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out keys/rsa-1024.key
"$openssl" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out keys/ec-p256.key
"$openssl" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out keys/ec-p384.key
"$openssl" genpkey -algorithm ED25519 -out keys/ed25519.key
"$openssl" genpkey -algorithm X25519 -out keys/x25519.key
"$openssl" genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:1024 -out keys/dsa.params
"$openssl" genpkey -paramfile keys/dsa.params -out keys/dsa-1024.key
rm keys/dsa.params
"$openssl" pkey -in keys/rsa-2048.key -traditional -out keys/rsa-2048-traditional.key
"$openssl" pkey -in keys/ec-p256.key -traditional -out keys/ec-p256-traditional.key
"$openssl" pkey -in keys/rsa-2048.key -pubout -out keys/rsa-2048-public.pem
"$openssl" rsa -in keys/rsa-2048.key -RSAPublicKey_out -out keys/rsa-2048-pkcs1-public.pem
"$openssl" pkey -in keys/ec-p256.key -outform DER -out keys/ec-p256.der
"$openssl" pkey -in keys/rsa-2048.key -aes256 -passout "$password" \
    -out keys/rsa-2048-encrypted.key
"$openssl" rsa -in keys/rsa-2048.key -traditional -aes256 -passout "$password" \
    -out keys/rsa-2048-encrypted-traditional.key
"$openssl" genpkey -genparam -algorithm DH -pkeyopt dh_paramgen_prime_len:1024 \
    -out keys/dhparam-1024.pem

# Certificates. Key usage decides the primitive a certificate key is reported with.
self_signed keys/rsa-2048.key sha256 rsa-2048 "keyUsage=digitalSignature,keyEncipherment" \
    certs/rsa-2048.crt
self_signed keys/rsa-1024.key sha1 rsa-1024-sha1 "keyUsage=digitalSignature" \
    certs/rsa-1024-sha1.pem
self_signed keys/ec-p256.key sha256 ec-p256 "keyUsage=digitalSignature" certs/ec-p256.pem
"$openssl" x509 -in certs/ec-p256.pem -outform DER -out certs/ec-p256.der
rm certs/ec-p256.pem
self_signed keys/ed25519.key sha256 ed25519 "keyUsage=keyCertSign,cRLSign" certs/ed25519.cer
"$openssl" req -new -key keys/ec-p384.key -sha384 -subj "/CN=ec-p384" -out certs/ec-p384.csr

# A bundle with the text openssl x509 -subject writes between certificates, and a file that
# holds a certificate and its key.
{
    echo "subject=CN=rsa-2048"
    cat certs/rsa-2048.crt
    echo
    echo "subject=CN=rsa-1024-sha1"
    cat certs/rsa-1024-sha1.pem
} >certs/bundle.pem
cat certs/rsa-2048.crt keys/ec-p256.key >certs/server.pem

# What a scanner must survive: cut, corrupted, empty, or not a certificate at all.
head -c 600 certs/rsa-2048.crt >broken/truncated.pem
head -c 200 certs/ec-p256.der >broken/truncated.der
{
    echo "-----BEGIN CERTIFICATE-----"
    echo "this is not base64 at all !!!"
    echo "-----END CERTIFICATE-----"
} >broken/garbage.pem
: >broken/empty.crt
echo "Ask the admin for the real key." >broken/notes.key
{
    cat certs/ec-p384.csr
    echo "-----BEGIN CERTIFICATE-----"
    echo "AAAA"
} >broken/good-then-cut.pem
