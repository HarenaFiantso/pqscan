/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_CORE_STATUS_H
#define PQSCAN_CORE_STATUS_H

/** Outcome of an operation that can fail. */
typedef enum pqscan_status {
    PQSCAN_OK = 0,
    PQSCAN_ERR_NOMEM,
    PQSCAN_ERR_IO,
    PQSCAN_ERR_NOT_FOUND,
    PQSCAN_ERR_NOT_REGULAR,
    PQSCAN_ERR_TOO_LARGE,
    PQSCAN_ERR_BINARY,
    PQSCAN_ERR_PARSE,
    PQSCAN_ERR_RULES,
    PQSCAN_ERR_BUDGET,
} pqscan_status;

/**
 * @brief Describe a status for a human reader.
 *
 * @param status The status to describe.
 * @return A short message. Never NULL. The string has static storage duration: the
 *         caller must not modify or free it.
 */
const char *pqscan_status_message(pqscan_status status);

#endif /* PQSCAN_CORE_STATUS_H */
