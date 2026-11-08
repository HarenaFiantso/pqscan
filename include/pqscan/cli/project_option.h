/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CLI_PROJECT_OPTION_H
#define PQSCAN_CLI_PROJECT_OPTION_H

#include "pqscan/risk/project_file.h"

/**
 * @brief Load the project a run asked for, and explain any failure on stderr.
 *
 * Without a path, a .pqscan.json in the current directory is read if there is one, and the
 * default project is used if there is none. A file that exists but cannot be used is an
 * error either way, because priorities computed without it would look right and be wrong.
 *
 * @param path The file given to --project, or NULL.
 * @param out On success, the project, owned by the caller and freed with project_destroy().
 *            Untouched on failure.
 * @return PQSCAN_EXIT_CLEAN, PQSCAN_EXIT_USAGE if the file cannot be used, or
 *         PQSCAN_EXIT_INTERNAL if memory runs out.
 */
int cli_load_project(const char *path, project **out);

#endif /* PQSCAN_CLI_PROJECT_OPTION_H */
