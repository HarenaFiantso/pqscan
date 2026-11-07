/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_FLOW_FLOW_SOURCE_H
#define PQSCAN_FLOW_FLOW_SOURCE_H

#include "pqscan/scan/file_reader.h"
#include "pqscan/scan/syntax_parser.h"
#include "pqscan/walk/file_type.h"

/** The file an analysis runs on. Everything is borrowed and must outlive the analysis. */
typedef struct flow_source {
    const file_contents *file;
    syntax_parser *parser;
    source_language language;
} flow_source;

#endif /* PQSCAN_FLOW_FLOW_SOURCE_H */
