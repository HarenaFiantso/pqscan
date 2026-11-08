/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_BASELINE_BASELINE_FORMAT_H
#define PQSCAN_BASELINE_BASELINE_FORMAT_H

#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"

/** Raised when a change could make an older pqscan misread a baseline. */
enum { BASELINE_SCHEMA_VERSION = 1 };

/**
 * What a baseline remembers of a finding: what it is and which file it is in.
 *
 * The line is left out, because it moves with every edit above the finding. So are the risk and
 * the priority, which follow from the rules and the date rather than from the code.
 */
typedef struct baseline_identity {
    const char *path; /**< Without leading "./", as relative_path_of() gives it. */
    const char *algorithm;
    const char *symbol;
    crypto_primitive primitive;
    key_size size;
} baseline_identity;

/**
 * @brief Tell what a baseline remembers of a finding.
 *
 * @param item The finding.
 * @return Its identity. The text is borrowed from @p item.
 */
baseline_identity baseline_identity_of(const finding *item);

/**
 * @brief Order two identities whose text is in the same form, field by field.
 *
 * @param left The first identity.
 * @param right The second identity.
 * @return Less than, equal to or greater than zero, as for qsort().
 */
int baseline_identity_compare(const baseline_identity *left, const baseline_identity *right);

/**
 * @brief Order the identity of a finding against one read back from a baseline file, whose
 *        text is in the safe form of safe_text.
 *
 * The order is the one baseline_identity_compare() gives two safe forms, so a list of identities
 * read from a file and sorted with it can be searched with this.
 *
 * @param raw The identity of a finding.
 * @param safe The identity from the file.
 * @return Less than, equal to or greater than zero, as for qsort().
 */
int baseline_identity_compare_safe(const baseline_identity *raw, const baseline_identity *safe);

#endif /* PQSCAN_BASELINE_BASELINE_FORMAT_H */
