/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/scan/elf_reader.h"

#include "pqscan/core/status.h"
#include "pqscan/walk/file_type.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Offsets, sizes and values from the System V ABI, "Object Files" chapter, for ELF64. The
 * input is never cast to a struct: its fields may be misaligned for this host, and their byte
 * order is the file's, not the host's. Each field is read one byte at a time instead.
 */
enum {
    EI_CLASS = 4,
    EI_DATA = 5,
    ELFCLASS64 = 2,
    ELFDATA2LSB = 1,
    ELFDATA2MSB = 2,
    EHDR_SIZE = 64,
    E_SHOFF = 0x28,
    E_SHENTSIZE = 0x3a,
    E_SHNUM = 0x3c,
};

enum {
    SHDR_SIZE = 64,
    SH_TYPE = 4,
    SH_OFFSET = 24,
    SH_SIZE = 32,
    SH_LINK = 40,
    SH_ENTSIZE = 56,
    SHT_SYMTAB = 2,
    SHT_STRTAB = 3,
    SHT_DYNSYM = 11,
};

enum {
    SYM_SIZE = 24,
    ST_NAME = 0,
    ST_INFO = 4,
    ST_SHNDX = 6,
    STT_NOTYPE = 0,
    STT_FUNC = 2,
    STT_GNU_IFUNC = 10,
    SHN_UNDEF = 0,
};

/* Field widths. ELF calls the last three Half, Word and Xword. */
enum { BYTE = 1, HALF = 2, WORD = 4, XWORD = 8 };

static const uint64_t STT_MASK = 0xfU; /* st_info keeps the type in its low four bits. */
static const unsigned BITS_PER_BYTE = 8U;

/* Where a field is in the input, and how many bytes it has. */
typedef struct elf_field {
    uint64_t offset;
    size_t width;
} elf_field;

/* The whole input, and how to decode it. */
typedef struct elf_view {
    const unsigned char *data;
    size_t len;
    bool big_endian;
} elf_view;

/* Once read, every header in the table is known to lie inside the input. */
typedef struct section_table {
    uint64_t offset;
    uint64_t count;
} section_table;

typedef struct elf_section {
    uint64_t type;
    uint64_t offset;
    uint64_t size;
    uint64_t link;
    uint64_t entry_size;
} elf_section;

typedef struct string_table {
    const char *data;
    size_t len;
} string_table;

typedef struct elf_reader {
    elf_view view;
    section_table sections;
    const elf_symbol_sink *sink;
} elf_reader;

/* Which kinds of table were met, since the ABI allows one of each. */
typedef struct table_search {
    bool seen_static;
    bool seen_dynamic;
    bool found;
    pqscan_status problem;
} table_search;

typedef enum name_lookup {
    NAME_FOUND,
    NAME_TOO_LONG,
    NAME_MALFORMED,
} name_lookup;

/* Written so that no sum can wrap: offset is checked first, then compared by subtraction. */
static bool fits(const elf_view *view, uint64_t offset, uint64_t size) {
    return offset <= view->len && size <= view->len - offset;
}

static elf_field byte_at(uint64_t offset) { return (elf_field){offset, BYTE}; }

static elf_field half_at(uint64_t offset) { return (elf_field){offset, HALF}; }

static elf_field word_at(uint64_t offset) { return (elf_field){offset, WORD}; }

static elf_field xword_at(uint64_t offset) { return (elf_field){offset, XWORD}; }

static bool read_field(const elf_view *view, elf_field field, uint64_t *value) {
    if (!fits(view, field.offset, field.width)) {
        return false;
    }
    const unsigned char *bytes = view->data + (size_t)field.offset;
    uint64_t result = 0;
    for (size_t i = 0; i < field.width; i++) {
        const size_t index = view->big_endian ? i : field.width - 1 - i;
        result = (result << BITS_PER_BYTE) | bytes[index];
    }
    *value = result;
    return true;
}

static pqscan_status open_view(const unsigned char *data, size_t len, elf_view *view) {
    if (!file_type_has_elf_magic(data, len) || len <= EI_CLASS) {
        return PQSCAN_ERR_ELF_MALFORMED;
    }
    /* Checked before the length, since a 32-bit header is shorter than a 64-bit one. */
    if (data[EI_CLASS] != ELFCLASS64) {
        return PQSCAN_ERR_ELF_UNSUPPORTED;
    }
    if (len < EHDR_SIZE) {
        return PQSCAN_ERR_ELF_MALFORMED;
    }
    const unsigned char encoding = data[EI_DATA];
    if (encoding != ELFDATA2LSB && encoding != ELFDATA2MSB) {
        return PQSCAN_ERR_ELF_MALFORMED;
    }
    view->data = data;
    view->len = len;
    view->big_endian = encoding == ELFDATA2MSB;
    return PQSCAN_OK;
}

/* With 0xff00 sections or more, e_shnum is 0 and the first header's sh_size holds the count. */
static bool read_section_count(const elf_view *view, uint64_t offset, uint64_t *count) {
    if (!read_field(view, half_at(E_SHNUM), count)) {
        return false;
    }
    return *count != 0 || read_field(view, xword_at(offset + SH_SIZE), count);
}

/* After this, offset + index * SHDR_SIZE + SHDR_SIZE <= len for every index below count. */
static pqscan_status read_section_table(const elf_view *view, section_table *table) {
    uint64_t offset = 0;
    uint64_t entry_size = 0;
    if (!read_field(view, xword_at(E_SHOFF), &offset) ||
        !read_field(view, half_at(E_SHENTSIZE), &entry_size)) {
        return PQSCAN_ERR_ELF_MALFORMED;
    }
    table->offset = offset;
    table->count = 0;
    if (offset == 0) {
        return PQSCAN_OK;
    }
    if (entry_size != SHDR_SIZE || !fits(view, offset, SHDR_SIZE) ||
        !read_section_count(view, offset, &table->count)) {
        return PQSCAN_ERR_ELF_MALFORMED;
    }
    const bool table_fits = table->count <= (view->len - offset) / SHDR_SIZE;
    return table_fits ? PQSCAN_OK : PQSCAN_ERR_ELF_MALFORMED;
}

static bool read_section(const elf_reader *reader, uint64_t index, elf_section *section) {
    if (index >= reader->sections.count) {
        return false;
    }
    const elf_view *view = &reader->view;
    const uint64_t start = reader->sections.offset + (index * SHDR_SIZE);
    return read_field(view, word_at(start + SH_TYPE), &section->type) &&
           read_field(view, xword_at(start + SH_OFFSET), &section->offset) &&
           read_field(view, xword_at(start + SH_SIZE), &section->size) &&
           read_field(view, word_at(start + SH_LINK), &section->link) &&
           read_field(view, xword_at(start + SH_ENTSIZE), &section->entry_size);
}

static bool read_string_table(const elf_reader *reader, uint64_t index, string_table *strings) {
    elf_section section;
    if (!read_section(reader, index, &section) || section.type != SHT_STRTAB ||
        !fits(&reader->view, section.offset, section.size)) {
        return false;
    }
    strings->data = (const char *)reader->view.data + (size_t)section.offset;
    strings->len = (size_t)section.size;
    return true;
}

/* Looks no further than one byte past the longest name reported, so each name costs O(1). */
static name_lookup find_name(const string_table *strings, uint64_t offset, elf_symbol *symbol) {
    if (offset >= strings->len) {
        return NAME_MALFORMED;
    }
    const char *start = strings->data + (size_t)offset;
    const size_t available = strings->len - (size_t)offset;
    const size_t searched =
        (available <= ELF_MAX_SYMBOL_NAME) ? available : ELF_MAX_SYMBOL_NAME + 1;
    const char *end = memchr(start, '\0', searched);
    if (end == NULL) {
        return (searched == available) ? NAME_MALFORMED : NAME_TOO_LONG;
    }
    symbol->name = start;
    symbol->len = (size_t)(end - start);
    return NAME_FOUND;
}

static elf_symbol_type symbol_type(uint64_t info) {
    switch (info & STT_MASK) {
    case STT_FUNC:
    case STT_GNU_IFUNC:
        return ELF_SYMBOL_FUNCTION;
    case STT_NOTYPE:
        return ELF_SYMBOL_UNTYPED;
    default:
        return ELF_SYMBOL_OTHER;
    }
}

static pqscan_status read_symbol(const elf_reader *reader, const string_table *strings,
                                 uint64_t start) {
    uint64_t name_offset = 0;
    uint64_t info = 0;
    uint64_t section_index = 0;
    if (!read_field(&reader->view, word_at(start + ST_NAME), &name_offset) ||
        !read_field(&reader->view, byte_at(start + ST_INFO), &info) ||
        !read_field(&reader->view, half_at(start + ST_SHNDX), &section_index)) {
        return PQSCAN_ERR_ELF_MALFORMED;
    }
    elf_symbol symbol = {NULL, 0, symbol_type(info), section_index != SHN_UNDEF};
    const name_lookup lookup = find_name(strings, name_offset, &symbol);
    if (lookup == NAME_TOO_LONG) {
        return PQSCAN_OK;
    }
    if (lookup == NAME_MALFORMED) {
        return PQSCAN_ERR_ELF_MALFORMED;
    }
    return reader->sink->visit(&symbol, reader->sink->context);
}

static bool symbol_table_fits(const elf_view *view, const elf_section *table) {
    return table->entry_size == SYM_SIZE && table->size % SYM_SIZE == 0 &&
           fits(view, table->offset, table->size);
}

static pqscan_status keep_first_problem(pqscan_status kept, pqscan_status status) {
    return (kept != PQSCAN_OK) ? kept : status;
}

/* Entry 0 is reserved and stands for no symbol at all. */
static pqscan_status read_symbol_table(const elf_reader *reader, const elf_section *table) {
    string_table strings;
    if (!symbol_table_fits(&reader->view, table) ||
        !read_string_table(reader, table->link, &strings)) {
        return PQSCAN_ERR_ELF_MALFORMED;
    }
    pqscan_status problem = PQSCAN_OK;
    for (uint64_t i = 1; i < table->size / SYM_SIZE; i++) {
        const pqscan_status status = read_symbol(reader, &strings, table->offset + (i * SYM_SIZE));
        if (status == PQSCAN_ERR_ELF_MALFORMED) {
            problem = keep_first_problem(problem, status);
        } else if (status != PQSCAN_OK) {
            return status;
        }
    }
    return problem;
}

static bool *seen_flag(table_search *search, uint64_t type) {
    if (type == SHT_SYMTAB) {
        return &search->seen_static;
    }
    return (type == SHT_DYNSYM) ? &search->seen_dynamic : NULL;
}

/* Reading one table per kind keeps the work linear, however many headers point at a table. */
static pqscan_status visit_section(const elf_reader *reader, table_search *search,
                                   const elf_section *section) {
    bool *seen = seen_flag(search, section->type);
    if (seen == NULL) {
        return PQSCAN_OK;
    }
    search->found = true;
    if (*seen) {
        search->problem = keep_first_problem(search->problem, PQSCAN_ERR_ELF_MALFORMED);
        return PQSCAN_OK;
    }
    *seen = true;
    const pqscan_status status = read_symbol_table(reader, section);
    if (status != PQSCAN_ERR_ELF_MALFORMED) {
        return status;
    }
    search->problem = keep_first_problem(search->problem, status);
    return PQSCAN_OK;
}

static pqscan_status read_symbol_tables(const elf_reader *reader) {
    table_search search = {false, false, false, PQSCAN_OK};
    for (uint64_t i = 0; i < reader->sections.count; i++) {
        elf_section section;
        if (!read_section(reader, i, &section)) {
            return PQSCAN_ERR_ELF_MALFORMED;
        }
        const pqscan_status status = visit_section(reader, &search, &section);
        if (status != PQSCAN_OK) {
            return status;
        }
    }
    return search.found ? search.problem : PQSCAN_ERR_ELF_NO_SYMBOLS;
}

pqscan_status elf_read_symbols(const unsigned char *data, size_t len, const elf_symbol_sink *sink) {
    elf_reader reader = {{NULL, 0, false}, {0, 0}, sink};
    pqscan_status status = open_view(data, len, &reader.view);
    if (status == PQSCAN_OK) {
        status = read_section_table(&reader.view, &reader.sections);
    }
    return (status == PQSCAN_OK) ? read_symbol_tables(&reader) : status;
}
