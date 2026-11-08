/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/finding.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/risk/risk.h"
#include "pqscan/rules/default_rules.h"
#include "pqscan/rules/rule_loader.h"
#include "pqscan/rules/rule_set.h"
#include "pqscan/scan/config_scanner.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/scanner.h"
#include "scan_support.h"
#include "unity.h"

#include <stdlib.h>
#include <string.h>

enum { DESCRIPTION_SIZE = 1024, HUGE_LINE_SIZE = 1024 * 1024, REPEATS = 100 };

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

static pqscan_status scan_bytes(const char *path, char *data, size_t len) {
    const file_contents file = {data, len};
    const scan_input input = {path, &file, rules};
    return config_scanner.scan(&input, findings);
}

static void assert_findings(const char *path, const char *text, const char *expected) {
    char *copy = malloc(strlen(text) + 1);
    TEST_ASSERT_NOT_NULL(copy);
    memcpy(copy, text, strlen(text) + 1);
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_bytes(path, copy, strlen(copy)));
    free(copy);
    char actual[DESCRIPTION_SIZE];
    describe_findings(findings, actual, sizeof(actual));
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, actual, text);
    finding_list_destroy(findings);
    findings = finding_list_create();
    TEST_ASSERT_NOT_NULL(findings);
}

static void test_accepts_config_files_only(void) {
    TEST_ASSERT_TRUE(config_scanner.accepts("etc/ssh/sshd_config"));
    TEST_ASSERT_TRUE(config_scanner.accepts("nginx.conf"));
    TEST_ASSERT_FALSE(config_scanner.accepts("a.c"));
}

static void test_reads_openssh_lists(void) {
    assert_findings("sshd_config",
                    "# KexAlgorithms diffie-hellman-group1-sha1\n"
                    "KexAlgorithms curve25519-sha256,diffie-hellman-group1-sha1,"
                    "mlkem768x25519-sha256\n"
                    "HostKeyAlgorithms ssh-ed25519,ssh-rsa,rsa-sha2-512,ecdsa-sha2-nistp256\n"
                    "Ciphers aes256-gcm@openssh.com,aes128-ctr,3des-cbc\n"
                    "MACs hmac-sha2-256,hmac-sha1\n",
                    "2:ECDH 2:DH-1024 3:EdDSA 3:SHA-1 3:RSA 3:ECDSA-256 4:AES-128 4:3DES 5:SHA-1");
}

static void test_openssh_keywords_ignore_case_and_may_use_equals(void) {
    assert_findings("ssh_config", "  kexalgorithms=+diffie-hellman-group14-sha1\n", "1:SHA-1");
}

static void test_a_removed_openssh_list_is_not_reported(void) {
    assert_findings("sshd_config", "PubkeyAcceptedAlgorithms -ssh-rsa,ssh-dss\n", "");
    assert_findings("sshd_config", "PubkeyAcceptedAlgorithms ^ssh-dss\n", "1:DSA-1024");
}

static void test_reads_nginx_settings(void) {
    assert_findings("nginx.conf",
                    "server {\n"
                    "    ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:!aNULL:!MD5';\n"
                    "    ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;\n"
                    "    ssl_conf_command Groups ffdhe2048;\n"
                    "}\n",
                    "2:ECDH 2:RSA 2:AES-128 3:ECDH 3:ECDH-256 4:DH-2048");
}

static void test_reads_apache_settings(void) {
    assert_findings("ssl.conf",
                    "<VirtualHost *:443>\n"
                    "SSLCipherSuite TLSv1.3 TLS_AES_128_GCM_SHA256\n"
                    "SSLCipherSuite \"DES-CBC3-SHA:\\\n"
                    "  RC4-SHA\"\n"
                    "SSLOpenSSLConfCmd SignatureAlgorithms RSA+SHA1:ed25519\n"
                    "</VirtualHost>\n",
                    "2:AES-128 3:3DES 3:SHA-1 4:RC4 4:SHA-1 5:RSA 5:SHA-1 5:EdDSA");
}

static void test_reads_openssl_cnf(void) {
    assert_findings("openssl.cnf",
                    "[system_default_sect]\n"
                    "CipherString = DEFAULT:@SECLEVEL=2\n"
                    "Groups = X448:P-384\n"
                    "[req]\n"
                    "default_bits = 1024\n"
                    "default_md = sha1\n",
                    "3:ECDH 3:ECDH-384 5:RSA-1024 6:SHA-1");
}

static void test_default_bits_that_cannot_be_read_is_unknown(void) {
    assert_findings("openssl.cnf", "default_bits = ${ENV::BITS}\n", "1:RSA-unknown");
    assert_findings("openssl.cnf", "default_bits = 99999999999999999999\n", "1:RSA-unknown");
    assert_findings("openssl.cnf", "default_bits = 0\n", "1:RSA-unknown");
    assert_findings("openssl.cnf", "default_bits = 4096\n", "1:RSA-4096");
    assert_findings("openssl.cnf", "default_bits\n", "");
}

static void test_a_conf_command_only_forwards_ssl_conf_commands(void) {
    assert_findings("nginx.conf", "ssl_conf_command Ciphers 3des-cbc;\n", "");
    assert_findings("nginx.conf", "ssl_conf_command;\n", "");
    assert_findings("nginx.conf", "ssl_conf_command Curves;\n", "");
}

static void test_reports_one_name_once_per_line_of_a_setting(void) {
    assert_findings("nginx.conf", "ssl_ciphers ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA;\n",
                    "1:ECDH 1:RSA 1:AES-128 1:SHA-1");
    assert_findings("nginx.conf", "ssl_ciphers RSA;\nssl_ciphers RSA;\n", "1:RSA 2:RSA");
}

static void test_reports_the_line_of_each_name(void) {
    assert_findings("nginx.conf", "ssl_ciphers \"ECDHE:\n    RSA\";\n", "1:ECDH 2:RSA");
}

static void test_names_outside_known_settings_are_ignored(void) {
    assert_findings("app.conf",
                    "Cipher ssh-rsa\n"
                    "comment = \"we dropped ssh-rsa\"\n"
                    "Ciphers_old 3des-cbc\n",
                    "");
}

static void test_records_what_matched(void) {
    char text[] = "Ciphers AES128-CTR\n";
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_bytes("sshd_config", text, strlen(text)));
    const finding *item = finding_list_get(findings, 0);
    TEST_ASSERT_NOT_NULL(item);
    TEST_ASSERT_EQUAL_STRING("sshd_config", item->path);
    TEST_ASSERT_EQUAL_STRING("aes128-ctr", item->symbol);
    TEST_ASSERT_EQUAL_INT(PRIMITIVE_ENCRYPTION, item->primitive);
    TEST_ASSERT_EQUAL_INT(RISK_REVIEW, item->risk);
    TEST_ASSERT_FALSE(item->expires.known);
}

static void test_an_empty_file_has_no_findings(void) {
    char text[] = "";
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_bytes("a.conf", text, 0));
    TEST_ASSERT_EQUAL_size_t(0, finding_list_count(findings));
}

static void test_skips_a_file_with_a_nul(void) {
    char text[] = "Ciphers 3des-cbc\n\0";
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_BINARY, scan_bytes("a.conf", text, sizeof(text) - 1));
    TEST_ASSERT_EQUAL_size_t(0, finding_list_count(findings));
}

static void test_reads_bytes_that_are_not_utf8(void) {
    assert_findings("a.conf", "# \xff\xfe\nCiphers \xe9,3des-cbc\n", "2:3DES");
}

static void test_reads_a_huge_line(void) {
    char *text = malloc(HUGE_LINE_SIZE + 1);
    TEST_ASSERT_NOT_NULL(text);
    memset(text, ':', HUGE_LINE_SIZE);
    memcpy(text, "ssl_ciphers RC4", strlen("ssl_ciphers RC4"));
    text[HUGE_LINE_SIZE] = '\0';
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, scan_bytes("a.conf", text, HUGE_LINE_SIZE));
    TEST_ASSERT_EQUAL_size_t(1, finding_list_count(findings));
    free(text);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_accepts_config_files_only);
    RUN_TEST(test_reads_openssh_lists);
    RUN_TEST(test_openssh_keywords_ignore_case_and_may_use_equals);
    RUN_TEST(test_a_removed_openssh_list_is_not_reported);
    RUN_TEST(test_reads_nginx_settings);
    RUN_TEST(test_reads_apache_settings);
    RUN_TEST(test_reads_openssl_cnf);
    RUN_TEST(test_default_bits_that_cannot_be_read_is_unknown);
    RUN_TEST(test_a_conf_command_only_forwards_ssl_conf_commands);
    RUN_TEST(test_reports_one_name_once_per_line_of_a_setting);
    RUN_TEST(test_reports_the_line_of_each_name);
    RUN_TEST(test_names_outside_known_settings_are_ignored);
    RUN_TEST(test_records_what_matched);
    RUN_TEST(test_an_empty_file_has_no_findings);
    RUN_TEST(test_skips_a_file_with_a_nul);
    RUN_TEST(test_reads_bytes_that_are_not_utf8);
    RUN_TEST(test_reads_a_huge_line);
    return UNITY_END();
}
