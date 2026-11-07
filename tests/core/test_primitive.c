/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/primitive.h"
#include "unity.h"

#include <stddef.h>

void setUp(void) {}

void tearDown(void) {}

static void test_names_match_the_rule_format(void) {
    TEST_ASSERT_EQUAL_STRING("unspecified", crypto_primitive_name(PRIMITIVE_UNSPECIFIED));
    TEST_ASSERT_EQUAL_STRING("signature", crypto_primitive_name(PRIMITIVE_SIGNATURE));
    TEST_ASSERT_EQUAL_STRING("key_exchange", crypto_primitive_name(PRIMITIVE_KEY_EXCHANGE));
    TEST_ASSERT_EQUAL_STRING("encryption", crypto_primitive_name(PRIMITIVE_ENCRYPTION));
    TEST_ASSERT_EQUAL_STRING("hash", crypto_primitive_name(PRIMITIVE_HASH));
}

static void test_parses_every_name(void) {
    const crypto_primitive primitives[] = {
        PRIMITIVE_UNSPECIFIED, PRIMITIVE_SIGNATURE, PRIMITIVE_KEY_EXCHANGE,
        PRIMITIVE_ENCRYPTION,  PRIMITIVE_HASH,
    };
    for (size_t i = 0; i < sizeof(primitives) / sizeof(primitives[0]); i++) {
        crypto_primitive parsed = PRIMITIVE_UNSPECIFIED;
        TEST_ASSERT_TRUE(crypto_primitive_parse(crypto_primitive_name(primitives[i]), &parsed));
        TEST_ASSERT_EQUAL_INT(primitives[i], parsed);
    }
}

static void test_rejects_other_names_and_leaves_the_output_alone(void) {
    crypto_primitive parsed = PRIMITIVE_HASH;
    TEST_ASSERT_FALSE(crypto_primitive_parse("Hash", &parsed));
    TEST_ASSERT_FALSE(crypto_primitive_parse("", &parsed));
    TEST_ASSERT_FALSE(crypto_primitive_parse("unknown", &parsed));
    TEST_ASSERT_EQUAL_INT(PRIMITIVE_HASH, parsed);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_names_match_the_rule_format);
    RUN_TEST(test_parses_every_name);
    RUN_TEST(test_rejects_other_names_and_leaves_the_output_alone);
    return UNITY_END();
}
