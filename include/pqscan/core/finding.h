/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CORE_FINDING_H
#define PQSCAN_CORE_FINDING_H

#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/risk/risk.h"

#include <stddef.h>

/** One use of cryptography found by a scanner. */
typedef struct finding {
    const char *path;           /**< File the finding is in. */
    size_t line;                /**< Line number, from 1. */
    const char *algorithm;      /**< Normalized name. Borrowed: see finding_list_add(). */
    risk_level risk;            /**< Urgency of the migration. */
    key_size size;              /**< Key size, if the algorithm has one. */
    crypto_primitive primitive; /**< What the use of the algorithm does. */
} finding;

/** A growable list of findings, in the order they were added. */
typedef struct finding_list finding_list;

/**
 * @brief Create an empty list.
 *
 * @return The list, owned by the caller and freed with finding_list_destroy(), or NULL
 *         if out of memory.
 */
finding_list *finding_list_create(void);

/**
 * @brief Free a list and every path it holds.
 *
 * @param list The list to free. May be NULL.
 */
void finding_list_destroy(finding_list *list);

/**
 * @brief Append a finding.
 *
 * @param list The list.
 * @param item The finding to copy. The list keeps its own copy of the path, so the
 *             caller's path need not outlive this call. It only borrows the algorithm,
 *             which must outlive the list. Scanners take it from a rule_set, which has to
 *             be destroyed after the list.
 * @return PQSCAN_OK, or PQSCAN_ERR_NOMEM.
 */
pqscan_status finding_list_add(finding_list *list, const finding *item);

/**
 * @brief Count the findings in a list.
 *
 * @param list The list.
 * @return The number of findings.
 */
size_t finding_list_count(const finding_list *list);

/**
 * @brief Read a finding by position.
 *
 * @param list The list.
 * @param index The position, from zero.
 * @return The finding, still owned by the list, or NULL if @p index is out of range. It
 *         stays valid until the next finding_list_add() or finding_list_destroy().
 */
const finding *finding_list_get(const finding_list *list, size_t index);

#endif /* PQSCAN_CORE_FINDING_H */
