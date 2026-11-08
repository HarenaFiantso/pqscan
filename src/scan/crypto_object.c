/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/scan/crypto_object.h"

#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/core/utc_time.h"
#include "pqscan/scan/pem_blocks.h"

#include <limits.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

enum { TM_YEAR_BASE = 1900, LAST_YEAR = 9999 };

/* A key usage extension lists bits, and KU_* names them. X509_get_key_usage() returns all bits
 * set when the extension is absent. */
static const uint32_t NO_KEY_USAGE = UINT32_MAX;
static const uint32_t SIGNING_USAGE =
    KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION | KU_KEY_CERT_SIGN | KU_CRL_SIGN;
static const uint32_t ENCRYPTING_USAGE = KU_KEY_ENCIPHERMENT | KU_DATA_ENCIPHERMENT;

/* What every use from one object shares. */
typedef struct object_context {
    const key_use_sink *sink;
    utc_time expires;
    bool has_usage;
    crypto_primitive usage;
} object_context;

/* DER to decode. OpenSSL takes lengths as long. */
typedef struct der_input {
    const unsigned char *data;
    long len;
} der_input;

/* The decoded parts of a PEM block, each allocated by OpenSSL. */
typedef struct pem_contents {
    char *label;
    char *header;
    unsigned char *data;
    long len;
} pem_contents;

/* Readers return PQSCAN_ERR_MALFORMED only when the input does not decode, never for what the
 * visitor returns, so that a DER file can be tried as one kind after another. */
typedef pqscan_status (*object_reader)(const der_input *input, const key_use_sink *sink);

typedef struct label_reader {
    const char *label;
    object_reader read;
} label_reader;

/* The labels of private keys that name their algorithm, which stays visible when the key
 * is encrypted. */
typedef struct legacy_key_label {
    const char *label;
    int type;
} legacy_key_label;

pqscan_status crypto_object_init(void) {
    return (OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) == 1) ? PQSCAN_OK
                                                                         : PQSCAN_ERR_NOMEM;
}

/* OBJ_nid2sn() and OBJ_nid2ln() name built-in objects from a static table, so the name
 * outlives the scan. Rules use short names, such as rsaEncryption. */
static const char *short_name(int nid) { return (nid > NID_undef) ? OBJ_nid2sn(nid) : NULL; }

/* The long name, such as sha256WithRSAEncryption, is what openssl x509 -text prints. */
static const char *long_name(int nid) { return (nid > NID_undef) ? OBJ_nid2ln(nid) : NULL; }

static key_use use_of(const object_context *context, const char *type_name) {
    const key_use use = {
        .type_name = type_name,
        .size = {KEY_SIZE_NOT_APPLICABLE, 0},
        .has_usage = context->has_usage,
        .usage = context->usage,
        .expires = context->expires,
    };
    return use;
}

static pqscan_status visit(const object_context *context, const key_use *use) {
    if (use->type_name == NULL) {
        return PQSCAN_OK;
    }
    return context->sink->visit(use, context->sink->context);
}

/* These curves have one size, which says nothing EdDSA or ECDH does not already say. */
static bool has_fixed_size(int type) {
    return type == EVP_PKEY_ED25519 || type == EVP_PKEY_ED448 || type == EVP_PKEY_X25519 ||
           type == EVP_PKEY_X448;
}

static key_size size_of(const EVP_PKEY *key) {
    const key_size none = {KEY_SIZE_NOT_APPLICABLE, 0};
    if (has_fixed_size(EVP_PKEY_get_base_id(key))) {
        return none;
    }
    const int bits = EVP_PKEY_get_bits(key);
    const key_size known = {KEY_SIZE_KNOWN, (unsigned)bits};
    const key_size unknown = {KEY_SIZE_UNKNOWN, 0};
    return (bits > 0) ? known : unknown;
}

/* A key that only a provider knows, such as ML-DSA in OpenSSL 3.5, has a name but no NID. */
static const char *key_type_name(const EVP_PKEY *key) {
    const char *name = short_name(EVP_PKEY_get_base_id(key));
    return (name != NULL) ? name : EVP_PKEY_get0_type_name(key);
}

static pqscan_status visit_key(const object_context *context, const EVP_PKEY *key) {
    key_use use = use_of(context, key_type_name(key));
    use.size = size_of(key);
    return visit(context, &use);
}

/* A signature algorithm such as sha1WithRSAEncryption names a key type and a digest, and
 * each can be weak on its own. The key type alone can say too little: an EC key may sign or
 * agree on keys, so the signature's own name is offered to the rules first. */
static pqscan_status visit_signature(const object_context *context, int signature) {
    int digest = NID_undef;
    int key_type = NID_undef;
    if (OBJ_find_sigid_algs(signature, &digest, &key_type) != 1) {
        return PQSCAN_OK;
    }
    key_use use = use_of(context, short_name(key_type));
    use.signature_name = short_name(signature);
    use.symbol = long_name(signature);
    use.has_usage = true;
    use.usage = PRIMITIVE_SIGNATURE;
    const pqscan_status status = visit(context, &use);
    if (status != PQSCAN_OK) {
        return status;
    }
    use.type_name = short_name(digest);
    use.signature_name = NULL;
    use.has_usage = false;
    return visit(context, &use);
}

static bool consumed_all(const der_input *input, const unsigned char *end) {
    return end == input->data + input->len;
}

static X509 *decode_certificate(const der_input *input, bool trusted) {
    const unsigned char *pos = input->data;
    X509 *cert = trusted ? d2i_X509_AUX(NULL, &pos, input->len) : d2i_X509(NULL, &pos, input->len);
    if (cert != NULL && !consumed_all(input, pos)) {
        X509_free(cert);
        return NULL;
    }
    return cert;
}

static utc_time expiry_of(const X509 *cert) {
    struct tm moment;
    memset(&moment, 0, sizeof(moment));
    const ASN1_TIME *not_after = X509_get0_notAfter(cert);
    if (not_after == NULL || ASN1_TIME_to_tm(not_after, &moment) != 1) {
        return utc_time_none();
    }
    const int year = moment.tm_year + TM_YEAR_BASE;
    if (year < 0 || year > LAST_YEAR) {
        return utc_time_none();
    }
    const utc_time expires = {
        true, year, moment.tm_mon + 1, moment.tm_mday, moment.tm_hour, moment.tm_min, moment.tm_sec,
    };
    return expires;
}

static crypto_primitive primitive_of_usage(bool signs, bool encrypts) {
    if (signs) {
        return PRIMITIVE_SIGNATURE;
    }
    return encrypts ? PRIMITIVE_ENCRYPTION : PRIMITIVE_KEY_EXCHANGE;
}

/* A key that only signs is reported as a signature key, and so on. One that does several
 * things keeps what its rule says. */
static void read_key_usage(X509 *cert, object_context *context) {
    const uint32_t usage = X509_get_key_usage(cert);
    if (usage == NO_KEY_USAGE) {
        return;
    }
    const bool signs = (usage & SIGNING_USAGE) != 0;
    const bool encrypts = (usage & ENCRYPTING_USAGE) != 0;
    const bool agrees = (usage & KU_KEY_AGREEMENT) != 0;
    if ((int)signs + (int)encrypts + (int)agrees != 1) {
        return;
    }
    context->has_usage = true;
    context->usage = primitive_of_usage(signs, encrypts);
}

/* A certificate can carry a key this OpenSSL cannot load. Its algorithm is still named. */
static pqscan_status visit_certificate_key(const object_context *context, X509 *cert) {
    const EVP_PKEY *key = X509_get0_pubkey(cert);
    if (key != NULL) {
        return visit_key(context, key);
    }
    ASN1_OBJECT *algorithm = NULL;
    const X509_PUBKEY *public_key = X509_get_X509_PUBKEY(cert);
    if (public_key == NULL ||
        X509_PUBKEY_get0_param(&algorithm, NULL, NULL, NULL, public_key) != 1) {
        return PQSCAN_OK;
    }
    key_use use = use_of(context, short_name(OBJ_obj2nid(algorithm)));
    use.size.kind = KEY_SIZE_UNKNOWN;
    return visit(context, &use);
}

static pqscan_status describe_certificate(X509 *cert, const key_use_sink *sink) {
    object_context context = {sink, expiry_of(cert), false, PRIMITIVE_UNSPECIFIED};
    read_key_usage(cert, &context);
    const pqscan_status status = visit_certificate_key(&context, cert);
    if (status != PQSCAN_OK) {
        return status;
    }
    context.has_usage = false;
    return visit_signature(&context, X509_get_signature_nid(cert));
}

static pqscan_status read_any_certificate(const der_input *input, const key_use_sink *sink,
                                          bool trusted) {
    X509 *cert = decode_certificate(input, trusted);
    if (cert == NULL) {
        return PQSCAN_ERR_MALFORMED;
    }
    const pqscan_status status = describe_certificate(cert, sink);
    X509_free(cert);
    return status;
}

static pqscan_status read_certificate(const der_input *input, const key_use_sink *sink) {
    return read_any_certificate(input, sink, false);
}

static pqscan_status read_trusted_certificate(const der_input *input, const key_use_sink *sink) {
    return read_any_certificate(input, sink, true);
}

static object_context plain_context(const key_use_sink *sink) {
    const object_context context = {sink, utc_time_none(), false, PRIMITIVE_UNSPECIFIED};
    return context;
}

static pqscan_status read_request(const der_input *input, const key_use_sink *sink) {
    const unsigned char *pos = input->data;
    X509_REQ *request = d2i_X509_REQ(NULL, &pos, input->len);
    if (request == NULL || !consumed_all(input, pos)) {
        X509_REQ_free(request);
        return PQSCAN_ERR_MALFORMED;
    }
    const object_context context = plain_context(sink);
    const EVP_PKEY *key = X509_REQ_get0_pubkey(request);
    pqscan_status status = (key != NULL) ? visit_key(&context, key) : PQSCAN_OK;
    if (status == PQSCAN_OK) {
        status = visit_signature(&context, X509_REQ_get_signature_nid(request));
    }
    X509_REQ_free(request);
    return status;
}

typedef EVP_PKEY *(*key_decoder)(const der_input *input, const unsigned char **end);

static pqscan_status read_key_with(const der_input *input, const key_use_sink *sink,
                                   key_decoder decode) {
    const unsigned char *end = input->data;
    EVP_PKEY *key = decode(input, &end);
    if (key == NULL || !consumed_all(input, end)) {
        EVP_PKEY_free(key);
        return PQSCAN_ERR_MALFORMED;
    }
    const object_context context = plain_context(sink);
    const pqscan_status status = visit_key(&context, key);
    EVP_PKEY_free(key);
    return status;
}

/* Reads PKCS#8, and the traditional RSA, DSA and EC forms. */
static EVP_PKEY *decode_private_key(const der_input *input, const unsigned char **end) {
    return d2i_AutoPrivateKey(NULL, end, input->len);
}

static EVP_PKEY *decode_public_key(const der_input *input, const unsigned char **end) {
    return d2i_PUBKEY(NULL, end, input->len);
}

static EVP_PKEY *decode_rsa_public_key(const der_input *input, const unsigned char **end) {
    return d2i_PublicKey(EVP_PKEY_RSA, NULL, end, input->len);
}

static EVP_PKEY *decode_dh_parameters(const der_input *input, const unsigned char **end) {
    return d2i_KeyParams(EVP_PKEY_DH, NULL, end, input->len);
}

static EVP_PKEY *decode_dhx_parameters(const der_input *input, const unsigned char **end) {
    return d2i_KeyParams(EVP_PKEY_DHX, NULL, end, input->len);
}

static EVP_PKEY *decode_dsa_parameters(const der_input *input, const unsigned char **end) {
    return d2i_KeyParams(EVP_PKEY_DSA, NULL, end, input->len);
}

static EVP_PKEY *decode_ec_parameters(const der_input *input, const unsigned char **end) {
    return d2i_KeyParams(EVP_PKEY_EC, NULL, end, input->len);
}

static pqscan_status read_private_key(const der_input *input, const key_use_sink *sink) {
    return read_key_with(input, sink, decode_private_key);
}

static pqscan_status read_public_key(const der_input *input, const key_use_sink *sink) {
    return read_key_with(input, sink, decode_public_key);
}

static pqscan_status read_rsa_public_key(const der_input *input, const key_use_sink *sink) {
    return read_key_with(input, sink, decode_rsa_public_key);
}

static pqscan_status read_dh_parameters(const der_input *input, const key_use_sink *sink) {
    return read_key_with(input, sink, decode_dh_parameters);
}

static pqscan_status read_dhx_parameters(const der_input *input, const key_use_sink *sink) {
    return read_key_with(input, sink, decode_dhx_parameters);
}

static pqscan_status read_dsa_parameters(const der_input *input, const key_use_sink *sink) {
    return read_key_with(input, sink, decode_dsa_parameters);
}

static pqscan_status read_ec_parameters(const der_input *input, const key_use_sink *sink) {
    return read_key_with(input, sink, decode_ec_parameters);
}

/* PKCS#8 encrypts the algorithm along with the key, so nothing can be said without the
 * passphrase. */
static pqscan_status read_encrypted_key(const der_input *input, const key_use_sink *sink) {
    (void)input;
    (void)sink;
    return PQSCAN_ERR_ENCRYPTED;
}

static const label_reader LABEL_READERS[] = {
    {"CERTIFICATE", read_certificate},
    {"X509 CERTIFICATE", read_certificate},
    {"TRUSTED CERTIFICATE", read_trusted_certificate},
    {"CERTIFICATE REQUEST", read_request},
    {"NEW CERTIFICATE REQUEST", read_request},
    {"PUBLIC KEY", read_public_key},
    {"RSA PUBLIC KEY", read_rsa_public_key},
    {"PRIVATE KEY", read_private_key},
    {"RSA PRIVATE KEY", read_private_key},
    {"DSA PRIVATE KEY", read_private_key},
    {"EC PRIVATE KEY", read_private_key},
    {"ENCRYPTED PRIVATE KEY", read_encrypted_key},
    {"DH PARAMETERS", read_dh_parameters},
    {"X9.42 DH PARAMETERS", read_dhx_parameters},
    {"DSA PARAMETERS", read_dsa_parameters},
    {"EC PARAMETERS", read_ec_parameters},
};

static const legacy_key_label LEGACY_KEY_LABELS[] = {
    {"RSA PRIVATE KEY", EVP_PKEY_RSA},
    {"DSA PRIVATE KEY", EVP_PKEY_DSA},
    {"EC PRIVATE KEY", EVP_PKEY_EC},
};

/* Without labels, DER is ambiguous: an RSA public key in PKCS#1 also decodes as DH
 * parameters. Only the kinds a DER file is commonly saved as are tried. */
static const object_reader DER_READERS[] = {
    read_certificate,
    read_request,
    read_public_key,
    read_private_key,
};

static object_reader find_reader(const char *label) {
    for (size_t i = 0; i < sizeof(LABEL_READERS) / sizeof(LABEL_READERS[0]); i++) {
        if (strcmp(label, LABEL_READERS[i].label) == 0) {
            return LABEL_READERS[i].read;
        }
    }
    return NULL;
}

/* A traditional key encrypted by OpenSSL keeps its label and says so in a Proc-Type header. */
static bool is_encrypted(const pem_contents *pem) {
    return pem->header != NULL && strstr(pem->header, "ENCRYPTED") != NULL;
}

static pqscan_status read_hidden_key(const pem_contents *pem, const key_use_sink *sink) {
    for (size_t i = 0; i < sizeof(LEGACY_KEY_LABELS) / sizeof(LEGACY_KEY_LABELS[0]); i++) {
        if (strcmp(pem->label, LEGACY_KEY_LABELS[i].label) == 0) {
            const object_context context = plain_context(sink);
            key_use use = use_of(&context, short_name(LEGACY_KEY_LABELS[i].type));
            use.size.kind = KEY_SIZE_UNKNOWN;
            return visit(&context, &use);
        }
    }
    return PQSCAN_ERR_ENCRYPTED;
}

static pqscan_status read_pem_contents(const pem_contents *pem, const key_use_sink *sink) {
    if (is_encrypted(pem)) {
        return read_hidden_key(pem, sink);
    }
    const object_reader read = find_reader(pem->label);
    if (read == NULL) {
        return PQSCAN_OK;
    }
    const der_input input = {pem->data, pem->len};
    return read(&input, sink);
}

static pqscan_status decode_pem(const pem_block *block, pem_contents *pem) {
    if (block->len > (size_t)INT_MAX) {
        return PQSCAN_ERR_MALFORMED;
    }
    BIO *bio = BIO_new_mem_buf(block->text, (int)block->len);
    if (bio == NULL) {
        return PQSCAN_ERR_NOMEM;
    }
    const int decoded = PEM_read_bio(bio, &pem->label, &pem->header, &pem->data, &pem->len);
    BIO_free(bio);
    return (decoded == 1) ? PQSCAN_OK : PQSCAN_ERR_MALFORMED;
}

static void free_pem(pem_contents *pem) {
    OPENSSL_free(pem->label);
    OPENSSL_free(pem->header);
    OPENSSL_free(pem->data);
}

/* OpenSSL queues an error for every failed decode. The queue is cleared after each object so
 * that it never grows with the number of files. */
pqscan_status crypto_object_read_pem(const pem_block *block, const key_use_sink *sink) {
    pem_contents pem = {NULL, NULL, NULL, 0};
    pqscan_status status = decode_pem(block, &pem);
    if (status == PQSCAN_OK) {
        status = read_pem_contents(&pem, sink);
    }
    free_pem(&pem);
    ERR_clear_error();
    return status;
}

static bool is_encrypted_der(const der_input *input) {
    const unsigned char *pos = input->data;
    X509_SIG *encrypted = d2i_X509_SIG(NULL, &pos, input->len);
    const bool whole = encrypted != NULL && consumed_all(input, pos);
    X509_SIG_free(encrypted);
    return whole;
}

static pqscan_status read_first_kind(const der_input *input, const key_use_sink *sink) {
    for (size_t i = 0; i < sizeof(DER_READERS) / sizeof(DER_READERS[0]); i++) {
        const pqscan_status status = DER_READERS[i](input, sink);
        if (status != PQSCAN_ERR_MALFORMED) {
            return status;
        }
    }
    return is_encrypted_der(input) ? PQSCAN_ERR_ENCRYPTED : PQSCAN_ERR_MALFORMED;
}

pqscan_status crypto_object_read_der(const unsigned char *data, size_t len,
                                     const key_use_sink *sink) {
    if (len == 0 || len > (size_t)LONG_MAX) {
        return PQSCAN_ERR_MALFORMED;
    }
    const der_input input = {data, (long)len};
    const pqscan_status status = read_first_kind(&input, sink);
    ERR_clear_error();
    return status;
}
