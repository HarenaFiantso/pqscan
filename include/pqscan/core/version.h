/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CORE_VERSION_H
#define PQSCAN_CORE_VERSION_H

/**
 * @brief Report the pqscan version.
 *
 * @return The version as a "MAJOR.MINOR.PATCH" string. Never NULL. The string has
 *         static storage duration: the caller must not modify or free it.
 */
const char *pqscan_version(void);

#endif /* PQSCAN_CORE_VERSION_H */
