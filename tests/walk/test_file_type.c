/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/walk/file_type.h"
#include "unity.h"

#include <stddef.h>

void setUp(void) {}

void tearDown(void) {}

static void test_accepts_c_and_cpp_extensions(void) {
    TEST_ASSERT_TRUE(file_type_is_source("a.c"));
    TEST_ASSERT_TRUE(file_type_is_source("dir/a.h"));
    TEST_ASSERT_TRUE(file_type_is_source("a.cpp"));
    TEST_ASSERT_TRUE(file_type_is_source("a.hpp"));
    TEST_ASSERT_TRUE(file_type_is_source("a.tar.c"));
}

static void test_accepts_the_other_cpp_extensions(void) {
    static const char *const PATHS[] = {
        "a.cc", "a.cxx", "a.C", "a.hh", "a.hxx", "a.ipp", "a.inl", "a.tcc",
    };
    for (size_t i = 0; i < sizeof(PATHS) / sizeof(PATHS[0]); i++) {
        TEST_ASSERT_TRUE_MESSAGE(file_type_is_source(PATHS[i]), PATHS[i]);
        TEST_ASSERT_EQUAL_INT_MESSAGE(SOURCE_LANGUAGE_CPP, file_type_source_language(PATHS[i]),
                                      PATHS[i]);
    }
}

static void test_rejects_everything_else(void) {
    static const char *const PATHS[] = {
        "a.txt", "Makefile", "a.H.txt", "a.CC", "a.c.orig", "dir.c/README", "",
    };
    for (size_t i = 0; i < sizeof(PATHS) / sizeof(PATHS[0]); i++) {
        TEST_ASSERT_FALSE_MESSAGE(file_type_is_source(PATHS[i]), PATHS[i]);
    }
}

static void test_c_files_use_the_c_grammar(void) {
    TEST_ASSERT_EQUAL_INT(SOURCE_LANGUAGE_C, file_type_source_language("dir/a.c"));
    TEST_ASSERT_EQUAL_INT(SOURCE_LANGUAGE_C, file_type_source_language("a.tar.c"));
}

static void test_headers_and_cpp_files_use_the_cpp_grammar(void) {
    TEST_ASSERT_EQUAL_INT(SOURCE_LANGUAGE_CPP, file_type_source_language("a.h"));
    TEST_ASSERT_EQUAL_INT(SOURCE_LANGUAGE_CPP, file_type_source_language("a.cpp"));
    TEST_ASSERT_EQUAL_INT(SOURCE_LANGUAGE_CPP, file_type_source_language("a.hpp"));
}

static void test_accepts_config_files(void) {
    static const char *const PATHS[] = {
        "nginx.conf",
        "etc/apache2/mods-available/ssl.conf",
        "openssl.cnf",
        "etc/ssh/sshd_config",
        "ssh_config",
        "etc/ssh/sshd_config.d/50-hardening.conf",
        "www/.htaccess",
        "etc/nginx/sites-available/default",
        "sites-enabled/example.com",
    };
    for (size_t i = 0; i < sizeof(PATHS) / sizeof(PATHS[0]); i++) {
        TEST_ASSERT_TRUE_MESSAGE(file_type_is_config(PATHS[i]), PATHS[i]);
    }
}

static void test_rejects_other_files_as_config(void) {
    static const char *const PATHS[] = {
        "a.c",
        "a.conf.orig",
        "a.CONF",
        "my_sshd_config",
        "sshd_config.bak",
        "a.conf/README",
        "sites-available",
        "",
        "/",
        "sites-available-x/a",
        "xsites-enabled/a",
    };
    for (size_t i = 0; i < sizeof(PATHS) / sizeof(PATHS[0]); i++) {
        TEST_ASSERT_FALSE_MESSAGE(file_type_is_config(PATHS[i]), PATHS[i]);
    }
}

static void test_accepts_certificates_and_keys(void) {
    static const char *const PATHS[] = {
        "ca.pem", "certs/server.crt", "a.cer", "a.der", "tls/server.key", "a.csr",
    };
    for (size_t i = 0; i < sizeof(PATHS) / sizeof(PATHS[0]); i++) {
        TEST_ASSERT_TRUE_MESSAGE(file_type_is_crypto_object(PATHS[i]), PATHS[i]);
    }
    static const char *const OTHERS[] = {"a.c", "a.PEM", "a.pem.bak", "id_rsa", "a.pub", ""};
    for (size_t i = 0; i < sizeof(OTHERS) / sizeof(OTHERS[0]); i++) {
        TEST_ASSERT_FALSE_MESSAGE(file_type_is_crypto_object(OTHERS[i]), OTHERS[i]);
    }
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_accepts_c_and_cpp_extensions);
    RUN_TEST(test_accepts_the_other_cpp_extensions);
    RUN_TEST(test_rejects_everything_else);
    RUN_TEST(test_c_files_use_the_c_grammar);
    RUN_TEST(test_headers_and_cpp_files_use_the_cpp_grammar);
    RUN_TEST(test_accepts_config_files);
    RUN_TEST(test_rejects_other_files_as_config);
    RUN_TEST(test_accepts_certificates_and_keys);
    return UNITY_END();
}
