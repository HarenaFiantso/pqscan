/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/baseline/baseline.h"
#include "pqscan/baseline/baseline_writer.h"
#include "pqscan/core/finding.h"
#include "pqscan/core/json_fields.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/core/utc_time.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/risk.h"
#include "unity.h"

#include <stddef.h>
#include <stdio.h>

enum { OUTPUT_SIZE = 4096, BITS = 2048 };

static const key_size NO_SIZE = {KEY_SIZE_NOT_APPLICABLE, 0};
static const key_size UNRESOLVED = {KEY_SIZE_UNKNOWN, 0};
static const key_size KNOWN = {KEY_SIZE_KNOWN, BITS};

static finding_list *findings;
static char output[OUTPUT_SIZE];
static size_t output_len;

void setUp(void) {
    findings = finding_list_create();
    TEST_ASSERT_NOT_NULL(findings);
    output[0] = '\0';
    output_len = 0;
}

void tearDown(void) { finding_list_destroy(findings); }

static void add(const char *path, size_t line, const char *algorithm, key_size size) {
    const crypto_primitive primitive =
        (size.kind == KEY_SIZE_NOT_APPLICABLE) ? PRIMITIVE_HASH : PRIMITIVE_UNSPECIFIED;
    const finding item = {
        path,      line,      algorithm,       RISK_QUANTUM_VULNERABLE, size,
        primitive, algorithm, utc_time_none(), priority_none(),
    };
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, finding_list_add(findings, &item));
}

static void write_baseline(void) {
    FILE *file = tmpfile();
    TEST_ASSERT_NOT_NULL(file);
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, baseline_write(findings, file));
    const int rewound = fseek(file, 0, SEEK_SET);
    TEST_ASSERT_EQUAL_INT(0, rewound);
    output_len = fread(output, 1, sizeof(output) - 1, file);
    output[output_len] = '\0';
    const int closed = fclose(file);
    TEST_ASSERT_EQUAL_INT(0, closed);
}

static void test_an_empty_list_writes_an_empty_baseline(void) {
    write_baseline();
    TEST_ASSERT_EQUAL_STRING("{\n"
                             "  \"schema_version\": 1,\n"
                             "  \"findings\": []\n"
                             "}\n",
                             output);
}

static void test_identical_findings_become_one_sorted_entry(void) {
    add("./src/b.c", 9, "RSA", KNOWN);
    add("a.c", 1, "MD5", NO_SIZE);
    add("src/b.c", 2, "RSA", KNOWN);
    add("src/b.c", 3, "RSA", UNRESOLVED);
    write_baseline();
    TEST_ASSERT_EQUAL_STRING("{\n"
                             "  \"schema_version\": 1,\n"
                             "  \"findings\": [\n"
                             "    {\n"
                             "      \"path\": \"a.c\",\n"
                             "      \"algorithm\": \"MD5\",\n"
                             "      \"symbol\": \"MD5\",\n"
                             "      \"primitive\": \"hash\",\n"
                             "      \"key_size\": null,\n"
                             "      \"count\": 1\n"
                             "    },\n"
                             "    {\n"
                             "      \"path\": \"src/b.c\",\n"
                             "      \"algorithm\": \"RSA\",\n"
                             "      \"symbol\": \"RSA\",\n"
                             "      \"primitive\": \"unspecified\",\n"
                             "      \"key_size\": \"unknown\",\n"
                             "      \"count\": 1\n"
                             "    },\n"
                             "    {\n"
                             "      \"path\": \"src/b.c\",\n"
                             "      \"algorithm\": \"RSA\",\n"
                             "      \"symbol\": \"RSA\",\n"
                             "      \"primitive\": \"unspecified\",\n"
                             "      \"key_size\": 2048,\n"
                             "      \"count\": 2\n"
                             "    }\n"
                             "  ]\n"
                             "}\n",
                             output);
}

static void test_a_written_baseline_accepts_every_finding_it_was_written_from(void) {
    add("a\nb.c", 1, "MD5", NO_SIZE);
    add("dir\\x0a/\xff.c", 2, "RSA", KNOWN);
    add("dir\\x0a/\xff.c", 3, "RSA", KNOWN);
    add("./plain.c", 4, "RSA", UNRESOLVED);
    write_baseline();

    baseline *loaded = NULL;
    json_error error;
    const baseline_source source = {output, output_len};
    TEST_ASSERT_EQUAL_INT_MESSAGE(PQSCAN_OK, baseline_load(&source, &loaded, &error),
                                  error.message);
    TEST_ASSERT_EQUAL_size_t(4, baseline_remove_accepted(loaded, findings));
    TEST_ASSERT_EQUAL_size_t(0, baseline_unused(loaded));
    baseline_destroy(loaded);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_an_empty_list_writes_an_empty_baseline);
    RUN_TEST(test_identical_findings_become_one_sorted_entry);
    RUN_TEST(test_a_written_baseline_accepts_every_finding_it_was_written_from);
    return UNITY_END();
}
