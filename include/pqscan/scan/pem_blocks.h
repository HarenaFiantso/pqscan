/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_SCAN_PEM_BLOCKS_H
#define PQSCAN_SCAN_PEM_BLOCKS_H

#include <stdbool.h>
#include <stddef.h>

/** One "-----BEGIN label-----" block of a PEM file. It points into the scanned text. */
typedef struct pem_block {
    const char *label; /**< Such as "CERTIFICATE". Not NUL-terminated. */
    size_t label_len;
    const char *text; /**< From the BEGIN line to the end of the END line, or to where the
                           block stops when it has no END line. Not NUL-terminated. */
    size_t len;
    size_t line; /**< The line of the BEGIN marker, from 1. */
} pem_block;

/**
 * Finds the PEM blocks of a text, such as the certificates of a bundle.
 *
 * Blocks are found the way OpenSSL finds them: a BEGIN marker starts a line. A block runs to
 * its first END line, and one that has none stops before the next BEGIN marker or at the
 * end of the text, so a truncated block never swallows the next. What lies between blocks is
 * skipped. Decoding is left to OpenSSL, so this only needs to know where blocks are, which
 * also gives each one its line number.
 *
 * The finder does not allocate. Its fields are private.
 */
typedef struct pem_finder {
    const char *text;
    size_t len;
    size_t pos;  /* Always at the start of a line. */
    size_t line; /* The line pos is on. */
} pem_finder;

/**
 * @brief Start looking for blocks in a text.
 *
 * @param finder The finder.
 * @param text The text, which must outlive the finder and every block it returns. It need
 *             not be NUL-terminated, and is never read past @p len.
 * @param len The length of the text.
 */
void pem_finder_init(pem_finder *finder, const char *text, size_t len);

/**
 * @brief Find the next block.
 *
 * @param finder The finder.
 * @param block Out: the block, which points into the text.
 * @return true if a block was found, false when there are no more.
 */
bool pem_finder_next(pem_finder *finder, pem_block *block);

#endif /* PQSCAN_SCAN_PEM_BLOCKS_H */
