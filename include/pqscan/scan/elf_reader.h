/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_SCAN_ELF_READER_H
#define PQSCAN_SCAN_ELF_READER_H

#include "pqscan/core/status.h"

#include <stdbool.h>
#include <stddef.h>

/**
 * Longer symbol names are not reported. No rule names a function that long, and the cap keeps
 * a hostile string table, where every name runs to its end, from making a read quadratic.
 */
enum { ELF_MAX_SYMBOL_NAME = 512 };

/** What a symbol names, as far as finding cryptography goes. */
typedef enum elf_symbol_type {
    ELF_SYMBOL_FUNCTION = 0, /**< A function, or a GNU indirect function. */
    ELF_SYMBOL_UNTYPED,      /**< No type, which is how an object file refers to what it calls. */
    ELF_SYMBOL_OTHER,        /**< Data, a section, a source file, thread-local storage... */
} elf_symbol_type;

/** One entry of a symbol table. Everything is borrowed for the visit only. */
typedef struct elf_symbol {
    const char *name; /**< Points into the bytes being read. name[len] is a NUL. */
    size_t len;       /**< At most ELF_MAX_SYMBOL_NAME. */
    elf_symbol_type type;
    bool defined; /**< false for a symbol the file needs from elsewhere, such as a library. */
} elf_symbol;

/**
 * @brief Be told about one symbol.
 *
 * @param symbol The symbol.
 * @param context What the sink carries.
 * @return PQSCAN_OK to go on, anything else to stop with that status.
 */
typedef pqscan_status (*elf_symbol_visitor)(const elf_symbol *symbol, void *context);

/** Where symbols go. */
typedef struct elf_symbol_sink {
    elf_symbol_visitor visit;
    void *context;
} elf_symbol_sink;

/**
 * @brief Report the symbols of a 64-bit ELF file, from its symbol table and its dynamic
 *        symbol table, in file order.
 *
 * Every offset and size the file states is checked against the input before anything is
 * read through it, and fields are decoded in the byte order the file declares, so the input
 * can be anything. Nothing is allocated. Sections are found by their type, so a file whose
 * section names are missing or lie is still read. The reserved first entry of each table is
 * skipped.
 *
 * @param data The bytes of the file. Not modified.
 * @param len How many there are.
 * @param sink Where symbols go.
 * @return PQSCAN_OK; PQSCAN_ERR_ELF_UNSUPPORTED for an ELF file that is not 64-bit;
 *         PQSCAN_ERR_ELF_NO_SYMBOLS when the file has neither table, as a stripped static
 *         executable does; PQSCAN_ERR_ELF_MALFORMED for input that is not ELF, or whose
 *         header or section table does not fit, in which case nothing is reported, and also
 *         when a symbol table, its string table or a name does not fit, or a second table of
 *         one kind appears, in which case the symbols of the rest are still reported; or the
 *         first status other than PQSCAN_OK that the visitor returned.
 */
pqscan_status elf_read_symbols(const unsigned char *data, size_t len, const elf_symbol_sink *sink);

#endif /* PQSCAN_SCAN_ELF_READER_H */
