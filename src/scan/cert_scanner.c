/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/scan/cert_scanner.h"

#include "pqscan/core/finding.h"
#include "pqscan/core/key_size.h"
#include "pqscan/core/status.h"
#include "pqscan/risk/priority.h"
#include "pqscan/risk/risk.h"
#include "pqscan/rules/rule_set.h"
#include "pqscan/scan/crypto_object.h"
#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/pem_blocks.h"
#include "pqscan/scan/scanner.h"
#include "pqscan/walk/file_type.h"

#include <stdbool.h>
#include <stddef.h>

/* A DER file has no lines, so its findings are about the whole file. */
enum { WHOLE_FILE = 0 };

typedef struct cert_walk {
    const scan_input *input;
    finding_list *findings;
    size_t line; /* Of the block being read. */
} cert_walk;

// cppcheck-suppress constParameterCallback
static pqscan_status report_use(const key_use *use, void *context) {
    const cert_walk *walk = context;
    const crypto_rule *rule = rule_set_find_key_type(walk->input->rules, use->type_name);
    if (rule == NULL) {
        return PQSCAN_OK;
    }
    const finding item = {
        walk->input->path,
        walk->line,
        rule->algorithm->name,
        risk_classify(rule->algorithm, use->size),
        use->size,
        use->has_usage ? use->usage : rule->primitive,
        (use->symbol != NULL) ? use->symbol : rule->pattern,
        use->expires,
        priority_none(),
    };
    return finding_list_add(walk->findings, &item);
}

/* A block that cannot be read does not stop the others, but the file is not fully analyzed. */
static pqscan_status keep_first_problem(pqscan_status kept, pqscan_status status) {
    return (kept != PQSCAN_OK) ? kept : status;
}

static pqscan_status scan_pem(cert_walk *walk, pem_finder *finder, const key_use_sink *sink) {
    pqscan_status problem = PQSCAN_OK;
    pem_block block;
    while (pem_finder_next(finder, &block)) {
        walk->line = block.line;
        const pqscan_status status = crypto_object_read_pem(&block, sink);
        if (status == PQSCAN_ERR_ENCRYPTED || status == PQSCAN_ERR_MALFORMED) {
            problem = keep_first_problem(problem, status);
        } else if (status != PQSCAN_OK) {
            return status;
        }
    }
    return problem;
}

static pqscan_status scan_der(cert_walk *walk, const key_use_sink *sink) {
    const file_contents *file = walk->input->file;
    walk->line = WHOLE_FILE;
    return crypto_object_read_der((const unsigned char *)file->data, file->len, sink);
}

/* A file is PEM if it holds at least one block. Text around the blocks is skipped. */
static pqscan_status scan_crypto_object(const scan_input *input, finding_list *findings) {
    const pqscan_status ready = crypto_object_init();
    if (ready != PQSCAN_OK) {
        return ready;
    }
    cert_walk walk = {input, findings, WHOLE_FILE};
    const key_use_sink sink = {report_use, &walk};
    pem_finder finder;
    pem_finder_init(&finder, input->file->data, input->file->len);
    pem_finder probe = finder;
    pem_block first;
    if (pem_finder_next(&probe, &first)) {
        return scan_pem(&walk, &finder, &sink);
    }
    return scan_der(&walk, &sink);
}

const scanner cert_scanner = {"cert", file_type_is_crypto_object, scan_crypto_object};
