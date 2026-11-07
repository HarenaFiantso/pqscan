/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CORE_KEY_SIZE_H
#define PQSCAN_CORE_KEY_SIZE_H

/** What is known about the key size of a finding. */
typedef enum key_size_kind {
    KEY_SIZE_NOT_APPLICABLE = 0, /**< The finding has no key size, such as a hash. */
    KEY_SIZE_UNKNOWN,            /**< It has one, but the scanner could not resolve it. */
    KEY_SIZE_KNOWN,              /**< It has one, and bits holds it. */
} key_size_kind;

/** A key size. A plain 0 could not tell "no key size" from "not resolved". */
typedef struct key_size {
    key_size_kind kind;
    unsigned bits; /**< Only meaningful for KEY_SIZE_KNOWN. */
} key_size;

#endif /* PQSCAN_CORE_KEY_SIZE_H */
