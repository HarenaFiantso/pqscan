/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/baseline/baseline_format.h"

#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/relative_path.h"
#include "pqscan/core/safe_text.h"

#include <string.h>

/* strcmp() and safe_text_compare() both fit, which is what lets one order serve both cases. */
typedef int (*text_order)(const char *left, const char *right);

static int compare_numbers(unsigned left, unsigned right) {
    return (left > right) - (left < right);
}

static int compare_with(const baseline_identity *left, const baseline_identity *right,
                        text_order compare_text) {
    int order = compare_text(left->path, right->path);
    if (order == 0) {
        order = compare_text(left->algorithm, right->algorithm);
    }
    if (order == 0) {
        order = compare_text(left->symbol, right->symbol);
    }
    if (order == 0) {
        order = compare_numbers((unsigned)left->primitive, (unsigned)right->primitive);
    }
    return (order == 0) ? key_size_compare(left->size, right->size) : order;
}

baseline_identity baseline_identity_of(const finding *item) {
    const baseline_identity identity = {
        relative_path_of(item->path), item->algorithm, item->symbol, item->primitive, item->size,
    };
    return identity;
}

int baseline_identity_compare(const baseline_identity *left, const baseline_identity *right) {
    return compare_with(left, right, strcmp);
}

int baseline_identity_compare_safe(const baseline_identity *raw, const baseline_identity *safe) {
    return compare_with(raw, safe, safe_text_compare);
}
