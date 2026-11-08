/* SPDX-License-Identifier: Apache-2.0 */
#include "cJSON.h"
#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/skip_list.h"
#include "pqscan/core/status.h"
#include "pqscan/core/utc_time.h"
#include "pqscan/core/version.h"
#include "pqscan/report/cbom_report.h"
#include "pqscan/report/reporter.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/risk.h"
#include "unity.h"

#include <stdio.h>
#include <string.h>

enum {
    OUTPUT_SIZE = 16384,
    SAMPLE_LINE = 12,
    SAMPLE_BITS = 2048,
    SHORT_BITS = 1024,
    SAMPLE_YEAR = 2031,
    LOW_PRIORITY = 51,
    HIGH_PRIORITY = 89,
};

static const key_size NO_KEY_SIZE = {KEY_SIZE_NOT_APPLICABLE, 0};

static const finding CERTIFICATE_KEY = {
    "server.der",
    0,
    "RSA",
    RISK_QUANTUM_VULNERABLE,
    {KEY_SIZE_KNOWN, SAMPLE_BITS},
    PRIMITIVE_SIGNATURE,
    "rsaEncryption",
    {true, SAMPLE_YEAR, 5, 1, 12, 0, 0},
    {0, NULL, {false, 0, 0, 0, 0, IR8547_ACCEPTABLE}},
};

static finding_list *findings;
static skip_list *skipped;
static cJSON *document;

void setUp(void) {
    findings = finding_list_create();
    TEST_ASSERT_NOT_NULL(findings);
    skipped = skip_list_create();
    TEST_ASSERT_NOT_NULL(skipped);
    document = NULL;
}

void tearDown(void) {
    cJSON_Delete(document);
    skip_list_destroy(skipped);
    finding_list_destroy(findings);
}

static void add(const finding *item) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, item));
}

static void add_use(const char *algorithm, key_size size, crypto_primitive primitive) {
    const finding item = {
        "a.c",     SAMPLE_LINE,  algorithm,       RISK_QUANTUM_VULNERABLE, size,
        primitive, "the_symbol", utc_time_none(), priority_none(),
    };
    add(&item);
}

static void write_and_parse(void) {
    FILE *out = tmpfile();
    TEST_ASSERT_NOT_NULL(out);
    const scan_report report = {findings, skipped};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, cbom_reporter.write(&report, out));
    const int seek_result = fseek(out, 0, SEEK_SET);
    TEST_ASSERT_EQUAL_INT(0, seek_result);
    static char output[OUTPUT_SIZE];
    const size_t len = fread(output, 1, sizeof(output) - 1, out);
    output[len] = '\0';
    const int closed = fclose(out);
    TEST_ASSERT_EQUAL_INT(0, closed);
    document = cJSON_Parse(output);
    TEST_ASSERT_NOT_NULL_MESSAGE(document, output);
}

static const cJSON *field(const cJSON *object, const char *name) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, name);
    TEST_ASSERT_NOT_NULL_MESSAGE(item, name);
    return item;
}

static const cJSON *component(int index) {
    return cJSON_GetArrayItem(field(document, "components"), index);
}

static const cJSON *algorithm_properties(const cJSON *item) {
    return field(field(item, "cryptoProperties"), "algorithmProperties");
}

static const cJSON *occurrences(const cJSON *item) {
    return field(field(item, "evidence"), "occurrences");
}

/* The value of a property, or NULL if the object does not have it. */
static const char *property(const cJSON *object, const char *name) {
    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, field(object, "properties")) {
        if (strcmp(field(entry, "name")->valuestring, name) == 0) {
            return field(entry, "value")->valuestring;
        }
    }
    return NULL;
}

static void assert_primitive(const char *algorithm, crypto_primitive primitive,
                             const char *expected) {
    finding_list_destroy(findings);
    findings = finding_list_create();
    TEST_ASSERT_NOT_NULL(findings);
    cJSON_Delete(document);
    add_use(algorithm, NO_KEY_SIZE, primitive);
    write_and_parse();
    TEST_ASSERT_EQUAL_STRING_MESSAGE(
        expected, field(algorithm_properties(component(0)), "primitive")->valuestring, algorithm);
}

static void test_an_empty_bom_is_complete(void) {
    write_and_parse();
    TEST_ASSERT_EQUAL_STRING("CycloneDX", field(document, "bomFormat")->valuestring);
    TEST_ASSERT_EQUAL_STRING("1.6", field(document, "specVersion")->valuestring);
    TEST_ASSERT_EQUAL_INT(1, field(document, "version")->valueint);
    TEST_ASSERT_EQUAL_INT(0, cJSON_GetArraySize(field(document, "components")));
    TEST_ASSERT_EQUAL_STRING("true", property(field(document, "metadata"), "pqscan:scan-complete"));
}

static void test_names_the_tool(void) {
    write_and_parse();
    const cJSON *tools = field(field(field(document, "metadata"), "tools"), "components");
    const cJSON *tool = cJSON_GetArrayItem(tools, 0);
    TEST_ASSERT_EQUAL_STRING("pqscan", field(tool, "name")->valuestring);
    TEST_ASSERT_EQUAL_STRING(pqscan_version(), field(tool, "version")->valuestring);
}

static void test_runs_cannot_be_told_apart_by_random_fields(void) {
    write_and_parse();
    TEST_ASSERT_FALSE(cJSON_HasObjectItem(document, "serialNumber"));
    TEST_ASSERT_FALSE(cJSON_HasObjectItem(field(document, "metadata"), "timestamp"));
}

static void test_a_component_describes_its_algorithm(void) {
    add_use("RSA", (key_size){KEY_SIZE_KNOWN, SAMPLE_BITS}, PRIMITIVE_SIGNATURE);
    write_and_parse();
    const cJSON *item = component(0);
    TEST_ASSERT_EQUAL_STRING("cryptographic-asset", field(item, "type")->valuestring);
    TEST_ASSERT_EQUAL_STRING("RSA-2048", field(item, "name")->valuestring);
    TEST_ASSERT_EQUAL_STRING("crypto/RSA-2048/signature", field(item, "bom-ref")->valuestring);
    TEST_ASSERT_EQUAL_STRING("algorithm",
                             field(field(item, "cryptoProperties"), "assetType")->valuestring);
    TEST_ASSERT_EQUAL_STRING(
        "2048", field(algorithm_properties(item), "parameterSetIdentifier")->valuestring);
    TEST_ASSERT_EQUAL_STRING("QUANTUM_VULNERABLE", property(item, "pqscan:risk"));
    TEST_ASSERT_NULL(property(item, "pqscan:key-size"));
}

static void test_an_unresolved_key_size_is_not_guessed(void) {
    add_use("RSA", (key_size){KEY_SIZE_UNKNOWN, 0}, PRIMITIVE_SIGNATURE);
    write_and_parse();
    const cJSON *item = component(0);
    TEST_ASSERT_EQUAL_STRING("RSA", field(item, "name")->valuestring);
    TEST_ASSERT_EQUAL_STRING("crypto/RSA-unknown/signature", field(item, "bom-ref")->valuestring);
    TEST_ASSERT_FALSE(cJSON_HasObjectItem(algorithm_properties(item), "parameterSetIdentifier"));
    TEST_ASSERT_EQUAL_STRING("unknown", property(item, "pqscan:key-size"));
}

static void test_primitives_use_the_cyclonedx_names(void) {
    assert_primitive("RSA", PRIMITIVE_SIGNATURE, "signature");
    assert_primitive("DH", PRIMITIVE_KEY_EXCHANGE, "key-agree");
    assert_primitive("MD5", PRIMITIVE_HASH, "hash");
    assert_primitive("EC", PRIMITIVE_UNSPECIFIED, "unknown");
}

static void test_encryption_is_told_apart_by_algorithm(void) {
    assert_primitive("RSA", PRIMITIVE_ENCRYPTION, "pke");
    assert_primitive("AES-128", PRIMITIVE_ENCRYPTION, "block-cipher");
    assert_primitive("DES", PRIMITIVE_ENCRYPTION, "block-cipher");
    assert_primitive("3DES", PRIMITIVE_ENCRYPTION, "block-cipher");
    assert_primitive("RC4", PRIMITIVE_ENCRYPTION, "stream-cipher");
    assert_primitive("Custom", PRIMITIVE_ENCRYPTION, "unknown");
}

static void test_equal_assets_share_one_component(void) {
    const key_size bits = {KEY_SIZE_KNOWN, SAMPLE_BITS};
    add_use("RSA", bits, PRIMITIVE_SIGNATURE);
    add_use("DH", bits, PRIMITIVE_KEY_EXCHANGE);
    add_use("RSA", bits, PRIMITIVE_SIGNATURE);
    write_and_parse();
    TEST_ASSERT_EQUAL_INT(2, cJSON_GetArraySize(field(document, "components")));
    TEST_ASSERT_EQUAL_STRING("DH-2048", field(component(0), "name")->valuestring);
    TEST_ASSERT_EQUAL_STRING("RSA-2048", field(component(1), "name")->valuestring);
    TEST_ASSERT_EQUAL_INT(2, cJSON_GetArraySize(occurrences(component(1))));
}

static void test_a_key_size_or_primitive_makes_another_component(void) {
    add_use("RSA", (key_size){KEY_SIZE_KNOWN, SAMPLE_BITS}, PRIMITIVE_SIGNATURE);
    add_use("RSA", (key_size){KEY_SIZE_KNOWN, SHORT_BITS}, PRIMITIVE_SIGNATURE);
    add_use("RSA", (key_size){KEY_SIZE_KNOWN, SAMPLE_BITS}, PRIMITIVE_ENCRYPTION);
    add_use("RSA", (key_size){KEY_SIZE_UNKNOWN, 0}, PRIMITIVE_SIGNATURE);
    add_use("RSA", NO_KEY_SIZE, PRIMITIVE_SIGNATURE);
    write_and_parse();
    TEST_ASSERT_EQUAL_INT(5, cJSON_GetArraySize(field(document, "components")));
}

static void test_bits_only_count_when_they_are_known(void) {
    add_use("RSA", (key_size){KEY_SIZE_UNKNOWN, SAMPLE_BITS}, PRIMITIVE_SIGNATURE);
    add_use("RSA", (key_size){KEY_SIZE_UNKNOWN, SHORT_BITS}, PRIMITIVE_SIGNATURE);
    write_and_parse();
    TEST_ASSERT_EQUAL_INT(1, cJSON_GetArraySize(field(document, "components")));
}

static void test_occurrences_are_sorted_whatever_the_scan_order(void) {
    const finding later = {
        "b.c",           1,
        "RSA",           RISK_QUANTUM_VULNERABLE,
        NO_KEY_SIZE,     PRIMITIVE_SIGNATURE,
        "second",        utc_time_none(),
        priority_none(),
    };
    const finding earlier = {
        "a.c",           2,
        "RSA",           RISK_QUANTUM_VULNERABLE,
        NO_KEY_SIZE,     PRIMITIVE_SIGNATURE,
        "z_first",       utc_time_none(),
        priority_none(),
    };
    const finding earliest = {
        "a.c",           2,
        "RSA",           RISK_QUANTUM_VULNERABLE,
        NO_KEY_SIZE,     PRIMITIVE_SIGNATURE,
        "a_first",       utc_time_none(),
        priority_none(),
    };
    add(&later);
    add(&earlier);
    add(&earliest);
    write_and_parse();
    const cJSON *places = occurrences(component(0));
    const cJSON *first = cJSON_GetArrayItem(places, 0);
    TEST_ASSERT_EQUAL_STRING("a.c", field(first, "location")->valuestring);
    TEST_ASSERT_EQUAL_INT(2, field(first, "line")->valueint);
    TEST_ASSERT_EQUAL_STRING("a_first", field(first, "symbol")->valuestring);
    TEST_ASSERT_EQUAL_STRING("z_first",
                             field(cJSON_GetArrayItem(places, 1), "symbol")->valuestring);
    TEST_ASSERT_EQUAL_STRING("b.c", field(cJSON_GetArrayItem(places, 2), "location")->valuestring);
}

static void test_a_certificate_occurrence_has_no_line_and_tells_its_expiry(void) {
    add(&CERTIFICATE_KEY);
    write_and_parse();
    const cJSON *place = cJSON_GetArrayItem(occurrences(component(0)), 0);
    TEST_ASSERT_NULL(cJSON_GetObjectItemCaseSensitive(place, "line"));
    TEST_ASSERT_EQUAL_STRING("expires 2031-05-01T12:00:00Z",
                             field(place, "additionalContext")->valuestring);
}

static void add_ranked(const char *path, unsigned score) {
    priority rank = priority_none();
    rank.score = score;
    const finding item = {
        path,        SAMPLE_LINE,         "RSA",        RISK_QUANTUM_VULNERABLE,
        NO_KEY_SIZE, PRIMITIVE_SIGNATURE, "the_symbol", utc_time_none(),
        rank,
    };
    add(&item);
}

static void test_a_component_is_as_urgent_as_its_most_urgent_use(void) {
    add_ranked("lib/a.c", LOW_PRIORITY);
    add_ranked("pay/b.c", HIGH_PRIORITY);
    add_ranked("lib/c.c", LOW_PRIORITY);
    write_and_parse();
    TEST_ASSERT_EQUAL_INT(1, cJSON_GetArraySize(field(document, "components")));
    TEST_ASSERT_EQUAL_STRING("89", property(component(0), "pqscan:priority"));
}

static void test_says_what_was_not_analyzed(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, skip_list_add(skipped, "b.c", PQSCAN_ERR_BINARY));
    write_and_parse();
    const cJSON *metadata = field(document, "metadata");
    TEST_ASSERT_EQUAL_STRING("false", property(metadata, "pqscan:scan-complete"));
    TEST_ASSERT_EQUAL_STRING("b.c: skipped, binary file", property(metadata, "pqscan:unanalyzed"));
}

static void test_a_hostile_file_name_stays_inside_its_string(void) {
    const finding item = {
        "evil\",\"line\":1\n\xff.c",
        SAMPLE_LINE,
        "RSA",
        RISK_QUANTUM_VULNERABLE,
        NO_KEY_SIZE,
        PRIMITIVE_SIGNATURE,
        "x",
        utc_time_none(),
        priority_none(),
    };
    add(&item);
    write_and_parse();
    const cJSON *first = cJSON_GetArrayItem(occurrences(component(0)), 0);
    TEST_ASSERT_EQUAL_STRING("evil\",\"line\":1\\x0a\\xff.c",
                             field(first, "location")->valuestring);
    TEST_ASSERT_EQUAL_INT(SAMPLE_LINE, field(first, "line")->valueint);
}

static void test_reports_a_failed_write(void) {
    FILE *read_only = fopen("/dev/null", "r");
    TEST_ASSERT_NOT_NULL(read_only);
    const scan_report report = {findings, skipped};
    const pqscan_status status = cbom_reporter.write(&report, read_only);
    const int closed = fclose(read_only);
    TEST_ASSERT_EQUAL_INT(0, closed);
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_IO, status);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_an_empty_bom_is_complete);
    RUN_TEST(test_names_the_tool);
    RUN_TEST(test_runs_cannot_be_told_apart_by_random_fields);
    RUN_TEST(test_a_component_describes_its_algorithm);
    RUN_TEST(test_an_unresolved_key_size_is_not_guessed);
    RUN_TEST(test_primitives_use_the_cyclonedx_names);
    RUN_TEST(test_encryption_is_told_apart_by_algorithm);
    RUN_TEST(test_equal_assets_share_one_component);
    RUN_TEST(test_a_key_size_or_primitive_makes_another_component);
    RUN_TEST(test_bits_only_count_when_they_are_known);
    RUN_TEST(test_occurrences_are_sorted_whatever_the_scan_order);
    RUN_TEST(test_a_certificate_occurrence_has_no_line_and_tells_its_expiry);
    RUN_TEST(test_a_component_is_as_urgent_as_its_most_urgent_use);
    RUN_TEST(test_says_what_was_not_analyzed);
    RUN_TEST(test_a_hostile_file_name_stays_inside_its_string);
    RUN_TEST(test_reports_a_failed_write);
    return UNITY_END();
}
