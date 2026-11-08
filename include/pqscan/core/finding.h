/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CORE_FINDING_H
#define PQSCAN_CORE_FINDING_H

#include "pqscan/core/key_size.h"
#include "pqscan/core/primitive.h"
#include "pqscan/core/status.h"
#include "pqscan/core/utc_time.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/risk.h"

#include <stdbool.h>
#include <stddef.h>

/** One use of cryptography found by a scanner. */
typedef struct finding {
    const char *path;           /**< File the finding is in. */
    size_t line;                /**< Line number, from 1, or 0 when it is the whole file. */
    const char *algorithm;      /**< Normalized name. Borrowed: see finding_list_add(). */
    risk_level risk;            /**< Urgency of the migration. */
    key_size size;              /**< Key size, if the algorithm has one. */
    crypto_primitive primitive; /**< What the use of the algorithm does. */
    const char *symbol;         /**< What matched in the file. Borrowed like the algorithm. */
    utc_time expires;           /**< When the certificate it belongs to stops being valid. */
    priority priority;          /**< How soon to migrate it. Scanners leave priority_none(). */
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
 *             caller's path need not outlive this call. It only borrows the algorithm and
 *             the symbol, which must outlive the list. Scanners take them from a rule_set,
 *             which has to be destroyed after the list.
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
 *         stays valid until the next finding_list_add(), finding_list_remove_if() or
 *         finding_list_destroy().
 */
const finding *finding_list_get(const finding_list *list, size_t index);

/**
 * @brief Set the priority of one finding, which is all that may change after it is added.
 *
 * @param list The list.
 * @param index The position, from zero. Nothing happens if it is out of range.
 * @param value The priority. Its component is borrowed, so it must outlive the list.
 */
void finding_list_set_priority(finding_list *list, size_t index, priority value);

/**
 * @brief Reorder the findings.
 *
 * @param list The list.
 * @param compare A qsort() comparison, called with two pointers to findings. It must order
 *                every pair, as qsort() does not keep equal findings in their order.
 */
void finding_list_sort(finding_list *list, int (*compare)(const void *left, const void *right));

/**
 * @brief Tell whether a finding should go.
 *
 * @param item The finding.
 * @param context The context given to finding_list_remove_if().
 * @return true to remove it.
 */
typedef bool (*finding_filter)(const finding *item, void *context);

/**
 * @brief Remove the findings a filter picks, keeping the others in their order.
 *
 * @param list The list. It frees the path of every finding it removes.
 * @param matches Called once for each finding, in list order, so it may keep state across
 *                calls, such as how many of something it has already seen.
 * @param context Passed to @p matches, unchanged.
 * @return The number of findings removed.
 */
size_t finding_list_remove_if(finding_list *list, finding_filter matches, void *context);

/**
 * @brief Point at every finding, so that a reader can sort them without touching the list.
 *
 * @param list The list.
 * @return An array of finding_list_count() pointers in list order, owned by the caller and
 *         freed with free(), or NULL if out of memory. The findings still belong to the list,
 *         and the pointers stay valid until the next finding_list_add(),
 *         finding_list_remove_if() or finding_list_destroy().
 */
const finding **finding_list_pointers(const finding_list *list);

#endif /* PQSCAN_CORE_FINDING_H */
