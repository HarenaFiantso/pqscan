/* SPDX-License-Identifier: Apache-2.0 */
#include "elf_builder.h"

#include "unity.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum {
    EHDR_SIZE = 64,
    SHDR_SIZE = 64,
    ALIGNMENT = 8,
    EI_VERSION = 6,
    E_TYPE = 0x10,
    E_MACHINE = 0x12,
    E_VERSION = 0x14,
    E_EHSIZE = 0x34,
    ELFCLASS64 = 2,
    ELFDATA2LSB = 1,
    ELFDATA2MSB = 2,
    EV_CURRENT = 1,
    ET_REL = 1,
    EM_X86_64 = 62,
    SHT_STRTAB = 3,
    ST_INFO = 4,
    ST_SHNDX = 6,
    SOME_SECTION = 1, /* A defined symbol needs a section index other than SHN_UNDEF. */
};

/* The null section, then a string table and a symbol table for each kind. */
enum { MAX_SECTIONS = 5, MAX_SYMBOLS = 64 };

static const unsigned char MAGIC[] = {0x7f, 'E', 'L', 'F'};
static const unsigned BITS_PER_BYTE = 8U;
static const unsigned GLOBAL_BINDING = 0x10U; /* STB_GLOBAL, in the high four bits of st_info. */

typedef struct section_spec {
    uint64_t type;
    uint64_t offset;
    uint64_t size;
    uint64_t link;
    uint64_t entry_size;
} section_spec;

typedef struct layout {
    built_elf *elf;
    section_spec sections[MAX_SECTIONS];
    size_t count;
} layout;

void built_elf_put(built_elf *elf, elf_field field, uint64_t value) {
    TEST_ASSERT_TRUE(field.offset <= sizeof(elf->bytes) &&
                     field.width <= sizeof(elf->bytes) - field.offset);
    for (size_t i = 0; i < field.width; i++) {
        const size_t index = elf->big_endian ? field.width - 1 - i : i;
        elf->bytes[field.offset + index] = (unsigned char)(value >> (i * BITS_PER_BYTE));
    }
}

uint64_t built_elf_get(const built_elf *elf, elf_field field) {
    TEST_ASSERT_TRUE(field.offset <= elf->len && field.width <= elf->len - field.offset);
    uint64_t value = 0;
    for (size_t i = 0; i < field.width; i++) {
        const size_t index = elf->big_endian ? i : field.width - 1 - i;
        value = (value << BITS_PER_BYTE) | elf->bytes[field.offset + index];
    }
    return value;
}

static elf_field field_at(size_t offset, size_t width) { return (elf_field){offset, width}; }

static size_t reserve(built_elf *elf, size_t size) {
    TEST_ASSERT_TRUE(size <= sizeof(elf->bytes) - elf->len);
    const size_t start = elf->len;
    elf->len += size;
    return start;
}

static void align(built_elf *elf) {
    (void)reserve(elf, (ALIGNMENT - (elf->len % ALIGNMENT)) % ALIGNMENT);
}

static size_t add_section(layout *plan, const section_spec *section) {
    TEST_ASSERT_TRUE(plan->count < MAX_SECTIONS);
    plan->sections[plan->count] = *section;
    return plan->count++;
}

static size_t write_strings(built_elf *elf, const test_symbols *symbols, size_t *offsets) {
    const size_t start = reserve(elf, 1);
    for (size_t i = 0; i < symbols->count; i++) {
        const size_t len = strlen(symbols->items[i].name) + 1;
        offsets[i] = reserve(elf, len) - start;
        memcpy(elf->bytes + start + offsets[i], symbols->items[i].name, len);
    }
    return start;
}

static void write_symbol_kind(built_elf *elf, size_t entry, const test_symbol *symbol) {
    elf->bytes[entry + ST_INFO] = (unsigned char)(GLOBAL_BINDING | symbol->type);
    built_elf_put(elf, field_at(entry + ST_SHNDX, TEST_HALF), symbol->defined ? SOME_SECTION : 0);
}

static size_t add_table(layout *plan, const test_symbols *symbols, uint64_t type) {
    built_elf *elf = plan->elf;
    TEST_ASSERT_TRUE(symbols->count <= MAX_SYMBOLS);
    size_t names[MAX_SYMBOLS];
    const size_t strings = write_strings(elf, symbols, names);
    const section_spec string_section = {SHT_STRTAB, strings, elf->len - strings, 0, 0};
    const size_t string_index = add_section(plan, &string_section);
    align(elf);
    const size_t table = reserve(elf, (symbols->count + 1) * TEST_SYM_SIZE);
    for (size_t i = 0; i < symbols->count; i++) {
        const size_t entry = table + ((i + 1) * TEST_SYM_SIZE);
        built_elf_put(elf, field_at(entry + TEST_ST_NAME, TEST_WORD), names[i]);
        write_symbol_kind(elf, entry, &symbols->items[i]);
    }
    const section_spec table_section = {type, table, elf->len - table, string_index, TEST_SYM_SIZE};
    return add_section(plan, &table_section);
}

static void write_section_headers(const layout *plan, size_t start) {
    built_elf *elf = plan->elf;
    for (size_t i = 0; i < plan->count; i++) {
        const size_t header = start + (i * SHDR_SIZE);
        const section_spec *section = &plan->sections[i];
        built_elf_put(elf, field_at(header + TEST_SH_TYPE, TEST_WORD), section->type);
        built_elf_put(elf, field_at(header + TEST_SH_OFFSET, TEST_XWORD), section->offset);
        built_elf_put(elf, field_at(header + TEST_SH_SIZE, TEST_XWORD), section->size);
        built_elf_put(elf, field_at(header + TEST_SH_LINK, TEST_WORD), section->link);
        built_elf_put(elf, field_at(header + TEST_SH_ENTSIZE, TEST_XWORD), section->entry_size);
    }
}

static void write_file_header(built_elf *elf, size_t section_table) {
    memcpy(elf->bytes, MAGIC, sizeof(MAGIC));
    elf->bytes[TEST_EI_CLASS] = ELFCLASS64;
    elf->bytes[TEST_EI_DATA] = elf->big_endian ? ELFDATA2MSB : ELFDATA2LSB;
    elf->bytes[EI_VERSION] = EV_CURRENT;
    built_elf_put(elf, field_at(E_TYPE, TEST_HALF), ET_REL);
    built_elf_put(elf, field_at(E_MACHINE, TEST_HALF), EM_X86_64);
    built_elf_put(elf, field_at(E_VERSION, TEST_WORD), EV_CURRENT);
    built_elf_put(elf, field_at(E_EHSIZE, TEST_HALF), EHDR_SIZE);
    built_elf_put(elf, field_at(TEST_E_SHENTSIZE, TEST_HALF), SHDR_SIZE);
    built_elf_put(elf, field_at(TEST_E_SHNUM, TEST_HALF), elf->section_count);
    built_elf_put(elf, field_at(TEST_E_SHOFF, TEST_XWORD), section_table);
}

void elf_build(const elf_spec *spec, built_elf *elf) {
    memset(elf, 0, sizeof(*elf));
    elf->big_endian = spec->big_endian;
    layout plan = {elf, {{0, 0, 0, 0, 0}}, 1};
    (void)reserve(elf, EHDR_SIZE);
    if (spec->dynamics.items != NULL) {
        elf->dynamic_table = add_table(&plan, &spec->dynamics, TEST_SHT_DYNSYM);
    }
    if (spec->statics.items != NULL) {
        elf->static_table = add_table(&plan, &spec->statics, TEST_SHT_SYMTAB);
    }
    align(elf);
    const size_t section_table = reserve(elf, plan.count * SHDR_SIZE);
    elf->section_count = plan.count;
    write_section_headers(&plan, section_table);
    write_file_header(elf, section_table);
}

size_t built_elf_section(const built_elf *elf, size_t index) {
    TEST_ASSERT_TRUE(index < elf->section_count);
    const size_t table = (size_t)built_elf_get(elf, field_at(TEST_E_SHOFF, TEST_XWORD));
    return table + (index * SHDR_SIZE);
}

size_t built_elf_symbol(const built_elf *elf, size_t table, size_t index) {
    const size_t header = built_elf_section(elf, table);
    const size_t start = (size_t)built_elf_get(elf, field_at(header + TEST_SH_OFFSET, TEST_XWORD));
    return start + (index * TEST_SYM_SIZE);
}
