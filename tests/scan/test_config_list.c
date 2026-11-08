/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/status.h"
#include "pqscan/rules/rule_loader.h"
#include "pqscan/rules/rule_set.h"
#include "pqscan/scan/config_lexer.h"
#include "pqscan/scan/config_list.h"
#include "unity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { DESCRIPTION_SIZE = 512, HOSTILE_PARTS = 200000, STOP_AFTER = 2 };

static const char RULES[] =
    "{\"schema_version\":1,"
    "\"algorithms\":[{\"name\":\"X\",\"risk\":\"QUANTUM_VULNERABLE\"}],"
    "\"rules\":["
    "{\"pattern\":\"ECDHE\",\"kind\":\"config\",\"algorithm\":\"X\",\"primitive\":\"key_exchange\"}"
    ","
    "{\"pattern\":\"RSA\",\"kind\":\"config\",\"algorithm\":\"X\",\"primitive\":\"unspecified\"},"
    "{\"pattern\":\"RSA-PSS\",\"kind\":\"config\",\"algorithm\":\"X\",\"primitive\":\"signature\"},"
    "{\"pattern\":\"DES\",\"kind\":\"config\",\"algorithm\":\"X\",\"primitive\":\"encryption\"},"
    "{\"pattern\":\"DES-CBC3\",\"kind\":\"config\",\"algorithm\":\"X\",\"primitive\":"
    "\"encryption\"},"
    "{\"pattern\":\"SHA\",\"kind\":\"config\",\"algorithm\":\"X\",\"primitive\":\"hash\"},"
    "{\"pattern\":\"SHA1\",\"kind\":\"config\",\"algorithm\":\"X\",\"primitive\":\"hash\"},"
    "{\"pattern\":\"P-256\",\"kind\":\"config\",\"algorithm\":\"X\",\"primitive\":\"key_exchange\"}"
    ","
    "{\"pattern\":\"X25519\",\"kind\":\"config\",\"algorithm\":\"X\",\"primitive\":\"key_"
    "exchange\"},"
    "{\"pattern\":\"ssh-rsa\",\"kind\":\"config\",\"algorithm\":\"X\",\"primitive\":\"signature\"},"
    "{\"pattern\":\"ssh-ed25519\",\"kind\":\"config\",\"algorithm\":\"X\",\"primitive\":"
    "\"signature\"},"
    "{\"pattern\":\"RSA\",\"kind\":\"string\",\"algorithm\":\"X\",\"primitive\":\"unspecified\"},"
    "{\"pattern\":\"md5\",\"kind\":\"string\",\"algorithm\":\"X\",\"primitive\":\"hash\"}"
    "],\"calls\":[]}";

static rule_set *rules;

/* Collects matches as "line:pattern" words. */
typedef struct collected {
    char text[DESCRIPTION_SIZE];
    size_t count;
    size_t stop_after; /* Fail with PQSCAN_ERR_NOMEM after this many matches, or never if 0. */
} collected;

void setUp(void) {
    rule_error error;
    const rule_source source = {RULES, strlen(RULES)};
    TEST_ASSERT_EQUAL_INT_MESSAGE(PQSCAN_OK, rule_set_load(&source, &rules, &error), error.message);
}

void tearDown(void) { rule_set_destroy(rules); }

static pqscan_status collect(const config_match *match, void *context) {
    collected *out = context;
    const size_t used = strlen(out->text);
    const int written = snprintf(out->text + used, sizeof(out->text) - used, "%s%zu:%s",
                                 (used > 0) ? " " : "", match->line, match->rule->pattern);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(out->text) - used);
    out->count++;
    return (out->stop_after != 0 && out->count == out->stop_after) ? PQSCAN_ERR_NOMEM : PQSCAN_OK;
}

static pqscan_status match_into(collected *out, config_list_syntax syntax, const char *text,
                                size_t len) {
    const config_list_scan scan = {rules, syntax, collect, out};
    const config_word word = {text, len, 1};
    return config_list_match(&scan, &word);
}

static void assert_matches(config_list_syntax syntax, const char *text, const char *expected) {
    collected out = {"", 0, 0};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, match_into(&out, syntax, text, strlen(text)));
    TEST_ASSERT_EQUAL_STRING_MESSAGE(expected, out.text, text);
}

static void test_an_empty_word_names_nothing(void) {
    assert_matches(CONFIG_LIST_OPENSSL, "", "");
    assert_matches(CONFIG_LIST_SSH, "", "");
    assert_matches(CONFIG_LIST_SINGLE, "", "");
}

static void test_splits_an_openssl_list_on_every_separator(void) {
    assert_matches(CONFIG_LIST_OPENSSL, "ECDHE:RSA,X25519/P-256 SHA1\tDES",
                   "1:ECDHE 1:RSA 1:X25519 1:P-256 1:SHA1 1:DES");
}

static void test_ignores_case(void) {
    assert_matches(CONFIG_LIST_OPENSSL, "ecdhe:x25519", "1:ECDHE 1:X25519");
}

static void test_splits_a_cipher_name_into_parts(void) {
    assert_matches(CONFIG_LIST_OPENSSL, "ECDHE-RSA-AES128-GCM-SHA256", "1:ECDHE 1:RSA");
    assert_matches(CONFIG_LIST_OPENSSL, "ECDHE+AESGCM", "1:ECDHE");
}

static void test_prefers_the_longest_known_run_of_parts(void) {
    assert_matches(CONFIG_LIST_OPENSSL, "DES-CBC3-SHA", "1:DES-CBC3 1:SHA");
    assert_matches(CONFIG_LIST_OPENSSL, "EDH-RSA-DES-CBC3-SHA", "1:RSA 1:DES-CBC3 1:SHA");
    assert_matches(CONFIG_LIST_OPENSSL, "RSA-PSS+SHA256:RSA+SHA1", "1:RSA-PSS 1:RSA 1:SHA1");
    assert_matches(CONFIG_LIST_OPENSSL, "P-256", "1:P-256");
}

static void test_skips_entries_that_take_algorithms_away(void) {
    assert_matches(CONFIG_LIST_OPENSSL, "HIGH:!RSA:-SHA1:!ECDHE-RSA-DES-CBC3-SHA:X25519",
                   "1:X25519");
    assert_matches(CONFIG_LIST_OPENSSL, "DEFAULT:@SECLEVEL=2:@STRENGTH", "");
}

static void test_keeps_entries_that_only_reorder(void) {
    assert_matches(CONFIG_LIST_OPENSSL, "+RSA:?X25519:*P-256:?*ECDHE",
                   "1:RSA 1:X25519 1:P-256 1:ECDHE");
}

static void test_a_name_is_never_found_inside_another(void) {
    assert_matches(CONFIG_LIST_OPENSSL, "X25519MLKEM768:SecP256r1MLKEM768:RSAx:xDES", "");
}

static void test_empty_parts_and_entries_are_skipped(void) {
    assert_matches(CONFIG_LIST_OPENSSL, "::RSA--DES++:", "1:RSA 1:DES");
    assert_matches(CONFIG_LIST_OPENSSL, "-", "");
    assert_matches(CONFIG_LIST_OPENSSL, "+", "");
}

static void test_only_config_tokens_count(void) { assert_matches(CONFIG_LIST_OPENSSL, "md5", ""); }

static void test_counts_lines_inside_a_quoted_word(void) {
    assert_matches(CONFIG_LIST_OPENSSL, "ECDHE:\n  RSA:\n\n DES", "1:ECDHE 2:RSA 4:DES");
}

static void test_splits_an_ssh_list_on_commas_and_matches_names_whole(void) {
    assert_matches(CONFIG_LIST_SSH, "ssh-ed25519,ssh-rsa,rsa-sha2-256", "1:ssh-ed25519 1:ssh-rsa");
    assert_matches(CONFIG_LIST_SSH, "ssh-rsa-cert-v01@openssh.com", "");
    assert_matches(CONFIG_LIST_SSH, ",,SSH-RSA,", "1:ssh-rsa");
}

static void test_an_ssh_list_may_add_but_not_remove(void) {
    assert_matches(CONFIG_LIST_SSH, "+ssh-rsa", "1:ssh-rsa");
    assert_matches(CONFIG_LIST_SSH, "^ssh-rsa,ssh-ed25519", "1:ssh-rsa 1:ssh-ed25519");
    assert_matches(CONFIG_LIST_SSH, "-ssh-rsa,ssh-ed25519", "");
}

static void test_a_single_name_is_matched_whole(void) {
    assert_matches(CONFIG_LIST_SINGLE, "SHA1", "1:SHA1");
    assert_matches(CONFIG_LIST_SINGLE, "sha1:RSA", "");
}

static void test_never_reads_past_the_length(void) {
    assert_matches(CONFIG_LIST_SINGLE, "SHA1", "1:SHA1");
    collected out = {"", 0, 0};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK,
                          match_into(&out, CONFIG_LIST_OPENSSL, "RSA-PSS", strlen("RSA-P")));
    TEST_ASSERT_EQUAL_STRING("1:RSA", out.text);
}

static void test_stops_when_the_visitor_fails(void) {
    collected out = {"", 0, STOP_AFTER};
    TEST_ASSERT_EQUAL_INT(
        PQSCAN_ERR_NOMEM,
        match_into(&out, CONFIG_LIST_OPENSSL, "RSA:DES:SHA:SHA1", strlen("RSA:DES:SHA:SHA1")));
    TEST_ASSERT_EQUAL_size_t(STOP_AFTER, out.count);
    collected ssh = {"", 0, 1};
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_NOMEM, match_into(&ssh, CONFIG_LIST_SSH, "ssh-rsa,ssh-rsa",
                                                       strlen("ssh-rsa,ssh-rsa")));
    TEST_ASSERT_EQUAL_size_t(1, ssh.count);
}

/* Trying every run of parts would take about HOSTILE_PARTS squared lookups. */
static void test_a_hostile_entry_stays_linear(void) {
    const size_t len = 2 * HOSTILE_PARTS;
    char *text = malloc(len);
    TEST_ASSERT_NOT_NULL(text);
    for (size_t i = 0; i < len; i++) {
        text[i] = (i % 2 == 0) ? 'a' : '-';
    }
    collected out = {"", 0, 0};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, match_into(&out, CONFIG_LIST_OPENSSL, text, len));
    TEST_ASSERT_EQUAL_size_t(0, out.count);
    free(text);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_an_empty_word_names_nothing);
    RUN_TEST(test_splits_an_openssl_list_on_every_separator);
    RUN_TEST(test_ignores_case);
    RUN_TEST(test_splits_a_cipher_name_into_parts);
    RUN_TEST(test_prefers_the_longest_known_run_of_parts);
    RUN_TEST(test_skips_entries_that_take_algorithms_away);
    RUN_TEST(test_keeps_entries_that_only_reorder);
    RUN_TEST(test_a_name_is_never_found_inside_another);
    RUN_TEST(test_empty_parts_and_entries_are_skipped);
    RUN_TEST(test_only_config_tokens_count);
    RUN_TEST(test_counts_lines_inside_a_quoted_word);
    RUN_TEST(test_splits_an_ssh_list_on_commas_and_matches_names_whole);
    RUN_TEST(test_an_ssh_list_may_add_but_not_remove);
    RUN_TEST(test_a_single_name_is_matched_whole);
    RUN_TEST(test_never_reads_past_the_length);
    RUN_TEST(test_stops_when_the_visitor_fails);
    RUN_TEST(test_a_hostile_entry_stays_linear);
    return UNITY_END();
}
