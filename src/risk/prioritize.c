/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/risk/prioritize.h"

#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/project_file.h"

#include <stddef.h>
#include <string.h>

void prioritize_findings(finding_list *findings, const project *target, int as_of_year) {
    const priority_basis basis = {as_of_year, project_quantum_year(target)};
    for (size_t i = 0; i < finding_list_count(findings); i++) {
        const finding *item = finding_list_get(findings, i);
        const data_lifetime lifetime = project_lifetime_of(target, item->path);
        finding_list_set_priority(findings, i, priority_assess(item->risk, &lifetime, &basis));
    }
}

static int compare_numbers(size_t left, size_t right) { return (left > right) - (left < right); }

/* Everything after the place, in the order a report line shows it. */
static int compare_contents(const finding *left, const finding *right) {
    int order = compare_numbers((size_t)right->risk, (size_t)left->risk);
    if (order == 0) {
        order = strcmp(left->algorithm, right->algorithm);
    }
    if (order == 0) {
        order = key_size_compare(left->size, right->size);
    }
    if (order == 0) {
        order = compare_numbers((size_t)left->primitive, (size_t)right->primitive);
    }
    return (order == 0) ? strcmp(left->symbol, right->symbol) : order;
}

static int compare_priorities(const void *left, const void *right) {
    const finding *first = left;
    const finding *second = right;
    int order = compare_numbers(second->priority.score, first->priority.score);
    if (order == 0) {
        order = strcmp(first->path, second->path);
    }
    if (order == 0) {
        order = compare_numbers(first->line, second->line);
    }
    return (order == 0) ? compare_contents(first, second) : order;
}

void sort_by_priority(finding_list *findings) { finding_list_sort(findings, compare_priorities); }
