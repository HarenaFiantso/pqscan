/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_TESTS_SUPPORT_ELF_BUILDER_H
#define PQSCAN_TESTS_SUPPORT_ELF_BUILDER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Values and offsets of the System V ABI that tests corrupt or check. They are restated here
 * rather than shared with the reader, so that tests check the reader against the format and
 * not against itself.
 */
enum {
    TEST_EI_CLASS = 4,
    TEST_EI_DATA = 5,
    TEST_E_SHOFF = 0x28,
    TEST_E_SHENTSIZE = 0x3a,
    TEST_E_SHNUM = 0x3c,
    TEST_SH_TYPE = 4,
    TEST_SH_OFFSET = 24,
    TEST_SH_SIZE = 32,
    TEST_SH_LINK = 40,
    TEST_SH_ENTSIZE = 56,
    TEST_ST_NAME = 0,
    TEST_SYM_SIZE = 24,
    TEST_SHT_PROGBITS = 1,
    TEST_SHT_SYMTAB = 2,
    TEST_SHT_DYNSYM = 11,
};

/** Symbol types, as st_info holds them. */
enum {
    TEST_STT_NOTYPE = 0,
    TEST_STT_OBJECT = 1,
    TEST_STT_FUNC = 2,
    TEST_STT_GNU_IFUNC = 10,
};

/** Widths of ELF fields. */
enum { TEST_HALF = 2, TEST_WORD = 4, TEST_XWORD = 8 };

/** Where a field is, and how many bytes it has. */
typedef struct elf_field {
    size_t offset;
    size_t width;
} elf_field;

/** Room for every image a test builds. */
enum { ELF_BUILDER_CAPACITY = 8192 };

/** One symbol to put in a table. */
typedef struct test_symbol {
    const char *name;
    unsigned type; /**< A TEST_STT_* value. */
    bool defined;
} test_symbol;

/** The symbols of one table. A NULL list leaves the table, and its string table, out. */
typedef struct test_symbols {
    const test_symbol *items;
    size_t count;
} test_symbols;

/** What to build. */
typedef struct elf_spec {
    bool big_endian;
    test_symbols statics;  /**< For .symtab. */
    test_symbols dynamics; /**< For .dynsym, which comes first in the file. */
} elf_spec;

/** A built ELF64 relocatable object, with what tests need to find their way in it. */
typedef struct built_elf {
    unsigned char bytes[ELF_BUILDER_CAPACITY];
    size_t len;
    bool big_endian;
    size_t section_count;
    size_t static_table;  /**< Section index of .symtab, or 0 if there is none. */
    size_t dynamic_table; /**< Section index of .dynsym, or 0 if there is none. */
} built_elf;

/**
 * @brief Build an image: the header, each string table and symbol table, then the section
 *        header table. Section 0 is the reserved null section. Failure fails the test.
 *
 * @param spec What to build.
 * @param elf Out: the image.
 */
void elf_build(const elf_spec *spec, built_elf *elf);

/**
 * @brief Overwrite a field, in the image's byte order.
 *
 * @param elf The image.
 * @param field The field. It must fit in the image.
 * @param value The new value.
 */
void built_elf_put(built_elf *elf, elf_field field, uint64_t value);

/**
 * @brief Read a field, in the image's byte order.
 *
 * @param elf The image.
 * @param field The field. It must fit in the image.
 * @return The value.
 */
uint64_t built_elf_get(const built_elf *elf, elf_field field);

/**
 * @brief Find a section header.
 *
 * @param elf The image.
 * @param index The section index.
 * @return The offset of its header.
 */
size_t built_elf_section(const built_elf *elf, size_t index);

/**
 * @brief Find a symbol.
 *
 * @param elf The image.
 * @param table The section index of its table.
 * @param index The symbol's index in the table, where 0 is the reserved entry.
 * @return The offset of its entry.
 */
size_t built_elf_symbol(const built_elf *elf, size_t table, size_t index);

#endif /* PQSCAN_TESTS_SUPPORT_ELF_BUILDER_H */
