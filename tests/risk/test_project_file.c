/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/json_fields.h"
#include "pqscan/core/status.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/project_file.h"
#include "unity.h"

#include <stdio.h>
#include <string.h>

enum {
    DOCUMENT_SIZE = 4096,
    LONG_PATTERN = PROJECT_MAX_PATTERN_LENGTH + 1,
    FILE_QUANTUM_YEAR = 2033,
};

/* What VALID says, path by path. */
static const data_lifetime PAYMENTS = {"payments", 25, 7};
static const data_lifetime TELEMETRY = {"telemetry", 1, 4};
static const data_lifetime UNCLAIMED = {NULL, 2, 4};
static const data_lifetime NOTHING = {NULL, 0, 0};

static const char VALID[] =
    "{\n"
    "  \"schema_version\": 1,\n"
    "  \"quantum_year\": 2033,\n"
    "  \"secrecy_years\": 2,\n"
    "  \"migration_years\": 4,\n"
    "  \"components\": [\n"
    "    {\"name\": \"payments\", \"paths\": [\"src/pay/*\", \"*.pem\"], \"secrecy_years\": 25,\n"
    "     \"migration_years\": 7},\n"
    "    {\"name\": \"telemetry\", \"paths\": [\"src/*\"], \"secrecy_years\": 1},\n"
    "    {\"name\": \"shadowed\", \"paths\": [\"src/pay/card.c\"], \"secrecy_years\": 99}\n"
    "  ]\n"
    "}\n";

static project *loaded;
static json_error error;

void setUp(void) { loaded = NULL; }

void tearDown(void) { project_destroy(loaded); }

static pqscan_status load_text(const char *text) {
    const project_source source = {text, strlen(text)};
    return project_load(&source, &loaded, &error);
}

static void load_valid(void) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(PQSCAN_OK, load_text(VALID), error.message);
}

/* Puts one component in an otherwise valid document. */
static void load_component(const char *component) {
    char document[DOCUMENT_SIZE];
    const int written = snprintf(document, sizeof(document),
                                 "{\"schema_version\":1,\"components\":[%s]}", component);
    TEST_ASSERT_TRUE(written > 0 && (size_t)written < sizeof(document));
    (void)load_text(document);
}

static void assert_refused(const char *expected_message) {
    TEST_ASSERT_NULL_MESSAGE(loaded, "the document should have been refused");
    TEST_ASSERT_EQUAL_STRING(expected_message, error.message);
}

static void assert_lifetime(const char *path, const data_lifetime *expected) {
    const data_lifetime lifetime = project_lifetime_of(loaded, path);
    if (expected->component == NULL) {
        TEST_ASSERT_NULL(lifetime.component);
    } else {
        TEST_ASSERT_EQUAL_STRING(expected->component, lifetime.component);
    }
    TEST_ASSERT_EQUAL_INT(expected->secrecy_years, lifetime.secrecy_years);
    TEST_ASSERT_EQUAL_INT(expected->migration_years, lifetime.migration_years);
}

static void test_the_default_project_declares_nothing(void) {
    loaded = project_create_default();
    TEST_ASSERT_NOT_NULL(loaded);
    TEST_ASSERT_EQUAL_INT(PROJECT_DEFAULT_QUANTUM_YEAR, project_quantum_year(loaded));
    TEST_ASSERT_EQUAL_INT(IR8547_DISALLOWED_AFTER, project_quantum_year(loaded));
    assert_lifetime("src/a.c", &NOTHING);
}

static void test_a_minimal_file_is_the_default_project(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, load_text("{\"schema_version\": 1}"));
    TEST_ASSERT_EQUAL_STRING("", error.message);
    TEST_ASSERT_EQUAL_INT(PROJECT_DEFAULT_QUANTUM_YEAR, project_quantum_year(loaded));
    assert_lifetime("src/a.c", &NOTHING);
}

static void test_reads_the_quantum_year(void) {
    load_valid();
    TEST_ASSERT_EQUAL_INT(FILE_QUANTUM_YEAR, project_quantum_year(loaded));
}

static void test_the_first_matching_component_wins(void) {
    load_valid();
    assert_lifetime("src/pay/card.c", &PAYMENTS);
    assert_lifetime("src/metrics.c", &TELEMETRY);
}

static void test_a_pattern_can_match_the_last_component(void) {
    load_valid();
    assert_lifetime("deploy/certs/server.pem", &PAYMENTS);
}

static void test_a_leading_current_directory_does_not_matter(void) {
    load_valid();
    assert_lifetime("./src/pay/card.c", &PAYMENTS);
}

static void test_an_unclaimed_path_gets_the_project_defaults(void) {
    load_valid();
    assert_lifetime("lib/legacy.c", &UNCLAIMED);
}

static void test_refuses_text_that_is_not_json(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_PROJECT, load_text("{\n\"schema_version\": 1,\n}"));
    assert_refused("line 3: invalid JSON");
}

static void test_refuses_a_document_that_is_not_an_object(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_PROJECT, load_text("[]"));
    assert_refused("document: expected an object");
}

static void test_refuses_a_missing_or_other_schema_version(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_PROJECT, load_text("{}"));
    assert_refused("schema_version: missing");
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_PROJECT, load_text("{\"schema_version\": 2}"));
    assert_refused("schema_version: expected an integer in range");
}

static void test_refuses_an_unknown_field(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_PROJECT,
                          load_text("{\"schema_version\": 1, \"secrecy_year\": 10}"));
    assert_refused("secrecy_year: unknown field");
}

static void test_refuses_years_out_of_range(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_PROJECT,
                          load_text("{\"schema_version\": 1, \"secrecy_years\": -1}"));
    assert_refused("secrecy_years: expected an integer in range");
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_PROJECT,
                          load_text("{\"schema_version\": 1, \"migration_years\": 1001}"));
    assert_refused("migration_years: expected an integer in range");
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_PROJECT,
                          load_text("{\"schema_version\": 1, \"quantum_year\": 10000}"));
    assert_refused("quantum_year: expected an integer in range");
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_PROJECT,
                          load_text("{\"schema_version\": 1, \"secrecy_years\": 2.5}"));
    assert_refused("secrecy_years: expected an integer in range");
}

static void test_accepts_the_ends_of_every_range(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK,
                          load_text("{\"schema_version\": 1, \"quantum_year\": 1970,"
                                    " \"secrecy_years\": 0, \"migration_years\": 1000}"));
    TEST_ASSERT_EQUAL_INT(PRIORITY_MIN_YEAR, project_quantum_year(loaded));
    const data_lifetime longest = {NULL, 0, PRIORITY_MAX_SPAN_YEARS};
    assert_lifetime("a.c", &longest);
}

static void test_refuses_components_that_are_not_an_array(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_PROJECT,
                          load_text("{\"schema_version\": 1, \"components\": {}}"));
    assert_refused("components: expected an array");
}

static void test_refuses_a_component_that_is_not_an_object(void) {
    load_component("{\"name\": \"a\", \"paths\": [\"*\"]}, 3");
    assert_refused("components[1].entry: expected an object");
}

static void test_refuses_an_unknown_field_in_a_component(void) {
    load_component("{\"name\": \"a\", \"paths\": [\"*\"], \"owner\": \"me\"}");
    assert_refused("components[0].owner: unknown field");
}

static void test_refuses_a_repeated_field_in_a_component(void) {
    load_component("{\"name\": \"a\", \"name\": \"b\", \"paths\": [\"*\"]}");
    assert_refused("components[0].name: repeated field");
}

static void test_refuses_a_component_without_a_printable_name(void) {
    load_component("{\"paths\": [\"*\"]}");
    assert_refused("components[0].name: expected a string");
    load_component("{\"name\": \"\\u001b[31m\", \"paths\": [\"*\"]}");
    assert_refused("components[0].name: expected 1 to 128 printable ASCII characters");
}

static void test_refuses_a_repeated_component_name(void) {
    load_component("{\"name\": \"a\", \"paths\": [\"x\"]}, {\"name\": \"a\", \"paths\": [\"y\"]}");
    assert_refused("components[1].name: repeated");
}

static void test_refuses_a_component_without_patterns(void) {
    load_component("{\"name\": \"a\"}");
    assert_refused("components[0].paths: expected a non-empty array of patterns");
    load_component("{\"name\": \"a\", \"paths\": []}");
    assert_refused("components[0].paths: expected a non-empty array of patterns");
    load_component("{\"name\": \"a\", \"paths\": \"*\"}");
    assert_refused("components[0].paths: expected a non-empty array of patterns");
}

static void test_refuses_a_pattern_that_is_empty_too_long_or_not_a_string(void) {
    load_component("{\"name\": \"a\", \"paths\": [\"*\", \"\"]}");
    assert_refused("components[0].paths: expected patterns of 1 to 1024 bytes");
    load_component("{\"name\": \"a\", \"paths\": [7]}");
    assert_refused("components[0].paths: expected patterns of 1 to 1024 bytes");

    char pattern[LONG_PATTERN + 1];
    memset(pattern, 'a', LONG_PATTERN);
    pattern[LONG_PATTERN] = '\0';
    char component[DOCUMENT_SIZE];
    (void)snprintf(component, sizeof(component), "{\"name\": \"a\", \"paths\": [\"%s\"]}", pattern);
    load_component(component);
    assert_refused("components[0].paths: expected patterns of 1 to 1024 bytes");
}

static void test_refuses_component_years_out_of_range(void) {
    load_component("{\"name\": \"a\", \"paths\": [\"*\"], \"secrecy_years\": 1001}");
    assert_refused("components[0].secrecy_years: expected an integer in range");
}

static void test_reads_text_that_is_not_nul_terminated(void) {
    static const char text[] = "{\"schema_version\":1}x";
    const project_source source = {text, sizeof(text) - 2};
    TEST_ASSERT_EQUAL_INT(PQSCAN_OK, project_load(&source, &loaded, &error));
}

static void test_refuses_bytes_after_the_document(void) {
    TEST_ASSERT_EQUAL_INT(PQSCAN_ERR_PROJECT, load_text("{\"schema_version\": 1} {}"));
    assert_refused("line 1: invalid JSON");
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_the_default_project_declares_nothing);
    RUN_TEST(test_a_minimal_file_is_the_default_project);
    RUN_TEST(test_reads_the_quantum_year);
    RUN_TEST(test_the_first_matching_component_wins);
    RUN_TEST(test_a_pattern_can_match_the_last_component);
    RUN_TEST(test_a_leading_current_directory_does_not_matter);
    RUN_TEST(test_an_unclaimed_path_gets_the_project_defaults);
    RUN_TEST(test_refuses_text_that_is_not_json);
    RUN_TEST(test_refuses_a_document_that_is_not_an_object);
    RUN_TEST(test_refuses_a_missing_or_other_schema_version);
    RUN_TEST(test_refuses_an_unknown_field);
    RUN_TEST(test_refuses_years_out_of_range);
    RUN_TEST(test_accepts_the_ends_of_every_range);
    RUN_TEST(test_refuses_components_that_are_not_an_array);
    RUN_TEST(test_refuses_a_component_that_is_not_an_object);
    RUN_TEST(test_refuses_an_unknown_field_in_a_component);
    RUN_TEST(test_refuses_a_repeated_field_in_a_component);
    RUN_TEST(test_refuses_a_component_without_a_printable_name);
    RUN_TEST(test_refuses_a_repeated_component_name);
    RUN_TEST(test_refuses_a_component_without_patterns);
    RUN_TEST(test_refuses_a_pattern_that_is_empty_too_long_or_not_a_string);
    RUN_TEST(test_refuses_component_years_out_of_range);
    RUN_TEST(test_reads_text_that_is_not_nul_terminated);
    RUN_TEST(test_refuses_bytes_after_the_document);
    return UNITY_END();
}
