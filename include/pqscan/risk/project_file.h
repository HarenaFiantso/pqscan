/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_RISK_PROJECT_FILE_H
#define PQSCAN_RISK_PROJECT_FILE_H

#include "pqscan/core/json_fields.h"
#include "pqscan/core/status.h"
#include "pqscan/risk/priority.h"

#include <stddef.h>

/** The quantum year when the file gives none: when IR 8547 disallows RSA and ECC. */
enum { PROJECT_DEFAULT_QUANTUM_YEAR = IR8547_DISALLOWED_AFTER };

/** The longest path pattern a component may list. */
enum { PROJECT_MAX_PATTERN_LENGTH = 1024 };

/** The text of a project file. It need not be NUL-terminated. */
typedef struct project_source {
    const char *text;
    size_t len;
} project_source;

/** What a project says about how long its data must stay secret. */
typedef struct project project;

/**
 * @brief Make the project of a run that has no project file: no components, no secrecy, no
 *        migration time, and the default quantum year.
 *
 * @return The project, owned by the caller and freed with project_destroy(), or NULL if out
 *         of memory.
 */
project *project_create_default(void);

/**
 * @brief Build a project from the JSON text of a project file.
 *
 * Validation is as strict as for rules: an unknown field, a wrong type or an out-of-range
 * value refuses the whole file, because a typo would otherwise silently lower priorities.
 *
 * @param source The text.
 * @param out On success, the project, owned by the caller and freed with project_destroy().
 *            Untouched on failure.
 * @param error Out: on PQSCAN_ERR_PROJECT, what is wrong. Empty otherwise.
 * @return PQSCAN_OK, PQSCAN_ERR_NOMEM or PQSCAN_ERR_PROJECT.
 */
pqscan_status project_load(const project_source *source, project **out, json_error *error);

/**
 * @brief Free a project.
 *
 * @param target The project. May be NULL.
 */
void project_destroy(project *target);

/**
 * @brief Read the year the project assumes a quantum computer breaks RSA and ECC.
 *
 * @param target The project.
 * @return The year, from PRIORITY_MIN_YEAR to PRIORITY_MAX_YEAR.
 */
int project_quantum_year(const project *target);

/**
 * @brief Tell what the project says about the data behind a path.
 *
 * The first component with a pattern that matches the path, as path_pattern_matches()
 * understands it, gives its years. A path no component claims gets the project's defaults.
 *
 * @param target The project.
 * @param path The path, as the report names it.
 * @return The lifetime. Its component name is borrowed from the project, which must outlive it.
 */
data_lifetime project_lifetime_of(const project *target, const char *path);

#endif /* PQSCAN_RISK_PROJECT_FILE_H */
