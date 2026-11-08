/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/core/utc_time.h"
#include "pqscan/risk/risk.h"
#include "pqscan/rules/default_rules.h"
#include "pqscan/rules/rule_loader.h"
#include "pqscan/rules/rule_set.h"
#include "pqscan/scan/cert_scanner.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/scanner.h"
#include "scan_support.h"
#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { PATH_SIZE = 512, DESCRIPTION_SIZE = 512 };

static const unsigned BYTE_FLIP = 0xffU;

static finding_list *findings;
static rule_set *rules;

void setUp(void) {
    findings = finding_list_create();
    TEST_ASSERT_NOT_NULL(findings);
    rule_error error;
    const rule_source source = default_rules_source();
    TEST_ASSERT_EQUAL_INT_MESSAGE(PQSCAN_OK, rule_set_load(&source, &rules, &error), error.message);
}

void tearDown(void) {
    finding_list_destroy(findings);
    rule_set_destroy(rules);
}

static file_contents *read_fixture(const char *name) {
    char path[PATH_SIZE];
    const int written = snprintf(path, sizeof(path), "%s/%s", PQSCAN_CRYPTO_FIXTURES, name);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(path));
    file_contents *file = NULL;
    TEST_ASSERT_EQUAL_INT_MESSAGE(PQSCAN_OK, file_contents_read(path, &file), path);
    return file;
}

static pqscan_status scan_contents(const file_contents *file) {
    const scan_input input = {"fixture", file, rules};
    return cert_scanner.scan(&input, findings);
}

static pqscan_status scan_fixture(const char *name) {
    file_contents *file = read_fixture(name);
    const pqscan_status status = scan_contents(file);
    file_contents_destroy(file);
    return status;
}

static void assert_findings(const char *name, const char *expected) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(PQSCAN_OK, scan_fixture(name), name);
    char actual[DESCRIPTION_SIZE];
    describe_findings(findings, actual, sizeof(actual));
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, actual, name);
}

static const finding *nth(size_t index) {
    const finding *item = finding_list_get(findings, index);
    TEST_ASSERT_NOT_NULL(item);
    return item;
}

static void assert_expires(const finding *item, const char *expected) {
    char text[UTC_TIME_TEXT_SIZE];
    utc_time_format(&item->expires, text, sizeof(text));
    TEST_ASSERT_EQUAL_STRING(expected, text);
}

static void test_accepts_certificates_and_keys_only(void) {
    TEST_ASSERT_TRUE(cert_scanner.accepts("tls/server.pem"));
    TEST_ASSERT_TRUE(cert_scanner.accepts("server.key"));
    TEST_ASSERT_FALSE(cert_scanner.accepts("server.conf"));
}

static void test_a_certificate_gives_its_key_and_its_signature(void) {
    assert_findings("certs/rsa-2048.crt", "1:RSA-2048 1:RSA");
    const finding *key = nth(0);
    TEST_ASSERT_EQUAL_STRING("rsaEncryption", key->symbol);
    TEST_ASSERT_EQUAL_INT(RISK_QUANTUM_VULNERABLE, key->risk);
    TEST_ASSERT_EQUAL_INT(PRIMITIVE_UNSPECIFIED, key->primitive);
    assert_expires(key, "2031-05-01T12:00:00Z");
    const finding *signature = nth(1);
    TEST_ASSERT_EQUAL_STRING("sha256WithRSAEncryption", signature->symbol);
    TEST_ASSERT_EQUAL_INT(PRIMITIVE_SIGNATURE, signature->primitive);
    TEST_ASSERT_EQUAL_INT(KEY_SIZE_NOT_APPLICABLE, signature->size.kind);
    assert_expires(signature, "2031-05-01T12:00:00Z");
}

static void test_a_weak_key_and_digest_are_classically_weak(void) {
    assert_findings("certs/rsa-1024-sha1.pem", "1:RSA-1024 1:RSA 1:SHA-1");
    TEST_ASSERT_EQUAL_INT(RISK_CLASSICALLY_WEAK, nth(0)->risk);
    TEST_ASSERT_EQUAL_STRING("sha1WithRSAEncryption", nth(2)->symbol);
    TEST_ASSERT_EQUAL_INT(PRIMITIVE_HASH, nth(2)->primitive);
}

static void test_key_usage_says_what_a_certificate_key_does(void) {
    assert_findings("certs/ec-p256.der", "0:EC-256 0:EC");
    TEST_ASSERT_EQUAL_INT(PRIMITIVE_SIGNATURE, nth(0)->primitive);
    TEST_ASSERT_EQUAL_STRING("id-ecPublicKey", nth(0)->symbol);
}

static void test_reads_an_eddsa_certificate(void) {
    assert_findings("certs/ed25519.cer", "1:EdDSA 1:EdDSA");
    TEST_ASSERT_EQUAL_INT(KEY_SIZE_NOT_APPLICABLE, nth(0)->size.kind);
}

static void test_a_request_has_no_expiry(void) {
    assert_findings("certs/ec-p384.csr", "1:EC-384 1:EC");
    TEST_ASSERT_FALSE(nth(0)->expires.known);
}

static void test_names_the_line_of_each_block(void) {
    assert_findings("certs/bundle.pem", "2:RSA-2048 2:RSA 23:RSA-1024 23:RSA 23:SHA-1");
}

static void test_reads_a_certificate_and_a_key_in_one_file(void) {
    assert_findings("certs/server.pem", "1:RSA-2048 1:RSA 20:EC-256");
    TEST_ASSERT_FALSE(nth(2)->expires.known);
}

static void test_reads_keys_in_every_container(void) {
    static const char *const RSA_KEYS[] = {
        "keys/rsa-2048.key",
        "keys/rsa-2048-traditional.key",
        "keys/rsa-2048-public.pem",
        "keys/rsa-2048-pkcs1-public.pem",
    };
    for (size_t i = 0; i < sizeof(RSA_KEYS) / sizeof(RSA_KEYS[0]); i++) {
        assert_findings(RSA_KEYS[i], "1:RSA-2048");
        finding_list_destroy(findings);
        findings = finding_list_create();
        TEST_ASSERT_NOT_NULL(findings);
    }
    assert_findings("keys/ec-p256.der", "0:EC-256");
}

static void test_reads_every_key_type(void) {
    assert_findings("keys/ec-p256-traditional.key", "1:EC-256");
    assert_findings("keys/ed25519.key", "1:EC-256 1:EdDSA");
    assert_findings("keys/x25519.key", "1:EC-256 1:EdDSA 1:ECDH");
    TEST_ASSERT_EQUAL_INT(PRIMITIVE_KEY_EXCHANGE, nth(2)->primitive);
    assert_findings("keys/dsa-1024.key", "1:EC-256 1:EdDSA 1:ECDH 1:DSA-1024");
    TEST_ASSERT_EQUAL_INT(RISK_CLASSICALLY_WEAK, nth(3)->risk);
}

static void test_reads_dh_parameters(void) {
    assert_findings("keys/dhparam-1024.pem", "1:DH-1024");
    TEST_ASSERT_EQUAL_INT(RISK_CLASSICALLY_WEAK, nth(0)->risk);
    TEST_ASSERT_EQUAL_INT(PRIMITIVE_KEY_EXCHANGE, nth(0)->primitive);
}

static void test_an_encrypted_traditional_key_still_names_its_algorithm(void) {
    assert_findings("keys/rsa-2048-encrypted-traditional.key", "1:RSA-unknown");
}

static void test_an_encrypted_pkcs8_key_cannot_be_analyzed(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_ENCRYPTED, scan_fixture("keys/rsa-2048-encrypted.key"));
    TEST_ASSERT_EQUAL_size_t(0, finding_list_count(findings));
}

static void test_broken_files_cannot_be_analyzed(void) {
    static const char *const BROKEN[] = {
        "broken/truncated.pem", "broken/truncated.der", "broken/garbage.pem",
        "broken/empty.crt",     "broken/notes.key",
    };
    for (size_t i = 0; i < sizeof(BROKEN) / sizeof(BROKEN[0]); i++) {
        TEST_ASSERT_EQUAL_INT_MESSAGE(PQSCAN_ERR_MALFORMED, scan_fixture(BROKEN[i]), BROKEN[i]);
    }
    TEST_ASSERT_EQUAL_size_t(0, finding_list_count(findings));
}

static void test_a_broken_block_keeps_the_findings_of_the_others(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_MALFORMED, scan_fixture("broken/good-then-cut.pem"));
    char actual[DESCRIPTION_SIZE];
    describe_findings(findings, actual, sizeof(actual));
    TEST_ASSERT_EQUAL_STRING("1:EC-384 1:EC", actual);
}

static void test_blocks_of_other_kinds_give_nothing(void) {
    char text[] = "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n";
    const file_contents file = {text, strlen(text)};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_contents(&file));
    TEST_ASSERT_EQUAL_size_t(0, finding_list_count(findings));
}

static void test_rules_without_key_types_report_nothing(void) {
    static const char RULES[] =
        "{\"schema_version\":1,\"algorithms\":[],\"rules\":[],\"calls\":[]}";
    rule_set_destroy(rules);
    rule_error error;
    const rule_source source = {RULES, strlen(RULES)};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, rule_set_load(&source, &rules, &error));
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_fixture("certs/rsa-2048.crt"));
    TEST_ASSERT_EQUAL_size_t(0, finding_list_count(findings));
}

/* Every prefix of a valid file is a truncation a scanner must survive. */
static void assert_every_truncation_is_survived(const char *name) {
    file_contents *whole = read_fixture(name);
    for (size_t len = 0; len < whole->len; len++) {
        const file_contents cut = {whole->data, len};
        const pqscan_status status = scan_contents(&cut);
        TEST_ASSERT_TRUE_MESSAGE(status == PQSCAN_OK || status == PQSCAN_ERR_MALFORMED, name);
    }
    file_contents_destroy(whole);
}

static void test_survives_every_truncation(void) {
    assert_every_truncation_is_survived("certs/ec-p256.der");
    assert_every_truncation_is_survived("certs/rsa-2048.crt");
}

static void flip_byte(char *byte) {
    const unsigned flipped = (unsigned)(unsigned char)*byte ^ BYTE_FLIP;
    *byte = (char)(unsigned char)flipped;
}

static void test_survives_every_flipped_byte(void) {
    file_contents *whole = read_fixture("certs/ec-p256.der");
    for (size_t i = 0; i < whole->len; i++) {
        flip_byte(&whole->data[i]);
        const pqscan_status status = scan_contents(whole);
        TEST_ASSERT_TRUE(status == PQSCAN_OK || status == PQSCAN_ERR_MALFORMED);
        flip_byte(&whole->data[i]);
    }
    file_contents_destroy(whole);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_accepts_certificates_and_keys_only);
    RUN_TEST(test_a_certificate_gives_its_key_and_its_signature);
    RUN_TEST(test_a_weak_key_and_digest_are_classically_weak);
    RUN_TEST(test_key_usage_says_what_a_certificate_key_does);
    RUN_TEST(test_reads_an_eddsa_certificate);
    RUN_TEST(test_a_request_has_no_expiry);
    RUN_TEST(test_names_the_line_of_each_block);
    RUN_TEST(test_reads_a_certificate_and_a_key_in_one_file);
    RUN_TEST(test_reads_keys_in_every_container);
    RUN_TEST(test_reads_every_key_type);
    RUN_TEST(test_reads_dh_parameters);
    RUN_TEST(test_an_encrypted_traditional_key_still_names_its_algorithm);
    RUN_TEST(test_an_encrypted_pkcs8_key_cannot_be_analyzed);
    RUN_TEST(test_broken_files_cannot_be_analyzed);
    RUN_TEST(test_a_broken_block_keeps_the_findings_of_the_others);
    RUN_TEST(test_blocks_of_other_kinds_give_nothing);
    RUN_TEST(test_rules_without_key_types_report_nothing);
    RUN_TEST(test_survives_every_truncation);
    RUN_TEST(test_survives_every_flipped_byte);
    return UNITY_END();
}
