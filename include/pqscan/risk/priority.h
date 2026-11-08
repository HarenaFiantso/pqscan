/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PQSCAN_RISK_PRIORITY_H
#define PQSCAN_RISK_PRIORITY_H

#include "pqscan/risk/risk.h"

#include <stdbool.h>

/** The highest score. Only what is already broken today gets it. */
enum { PRIORITY_MAX_SCORE = 100 };

/** NIST IR 8547: quantum-vulnerable algorithms are deprecated after 2030, disallowed after 2035. */
enum { IR8547_DEPRECATED_AFTER = 2030, IR8547_DISALLOWED_AFTER = 2035 };

/** The years a run can score for, and the longest secrecy or migration it accepts. Inputs in
 *  these ranges keep every sum in priority_assess() far from overflowing an int. */
enum { PRIORITY_MIN_YEAR = 1970, PRIORITY_MAX_YEAR = 9999, PRIORITY_MAX_SPAN_YEARS = 1000 };

/** Where NIST IR 8547 puts a quantum-vulnerable algorithm in a given year. */
typedef enum ir8547_status {
    IR8547_ACCEPTABLE = 0,
    IR8547_DEPRECATED,
    IR8547_DISALLOWED,
} ir8547_status;

/** What a run assumes about time. */
typedef struct priority_basis {
    int as_of_year;   /**< The year the run scores for. */
    int quantum_year; /**< The year a quantum computer is assumed to break RSA and ECC. */
} priority_basis;

/** What a project says about the data behind one path. */
typedef struct data_lifetime {
    const char *component; /**< The component the path belongs to, or NULL. Borrowed. */
    int secrecy_years;     /**< How long the data must stay confidential: Mosca's X. */
    int migration_years;   /**< How long moving to post-quantum crypto takes: Mosca's Y. */
} data_lifetime;

/** Mosca's theorem and IR 8547 applied to one quantum-vulnerable finding. */
typedef struct quantum_timeline {
    bool applies;           /**< false unless the finding is QUANTUM_VULNERABLE. The rest is
                                 then 0. */
    int secrecy_years;      /**< X. */
    int migration_years;    /**< Y. */
    int years_to_quantum;   /**< Q: the years left before the quantum year. Negative once it
                                 has passed. */
    int migration_end_year; /**< When a migration started in the as-of year would end. */
    ir8547_status status;   /**< Where IR 8547 puts the algorithm in that year. */
} quantum_timeline;

/** How soon a finding should be migrated. */
typedef struct priority {
    unsigned score;            /**< From 0 to PRIORITY_MAX_SCORE. Higher is more urgent. */
    const char *component;     /**< Copied from the data_lifetime, so borrowed the same way. */
    quantum_timeline timeline; /**< Why a quantum-vulnerable finding got its score. */
} priority;

/**
 * @brief Make the priority of a finding nothing has scored yet.
 *
 * @return A priority with a score of 0, no component, and a timeline that does not apply.
 */
priority priority_none(void);

/**
 * @brief Score one finding.
 *
 * OK scores 0, REVIEW 10 and CLASSICALLY_WEAK 100. QUANTUM_VULNERABLE scores from 50 to 99:
 * 50, plus 10 if IR 8547 deprecates the algorithm in the year the migration would end or 20
 * if it disallows it, plus 10 + X + Y - Q kept between 0 and 29, so that a finding is
 * exposed under Mosca's theorem exactly when this last term is over 10.
 *
 * @param risk The finding's risk level.
 * @param lifetime What the project says about the finding's path. Its years must be from 0 to
 *                 PRIORITY_MAX_SPAN_YEARS.
 * @param basis The years to score with, from PRIORITY_MIN_YEAR to PRIORITY_MAX_YEAR.
 * @return The priority. Its component is borrowed from @p lifetime.
 */
priority priority_assess(risk_level risk, const data_lifetime *lifetime,
                         const priority_basis *basis);

/**
 * @brief Tell whether Mosca's X + Y > Q holds: the data would still need to be secret when a
 *        quantum computer can read it.
 *
 * @param timeline The timeline.
 * @return true if the timeline applies and the inequality holds.
 */
bool quantum_timeline_exposed(const quantum_timeline *timeline);

/**
 * @brief Name an IR 8547 status as it appears in reports.
 *
 * @param status The status.
 * @return "acceptable", "deprecated" or "disallowed". Never NULL. The string has static
 *         storage duration: the caller must not modify or free it.
 */
const char *ir8547_status_name(ir8547_status status);

#endif /* PQSCAN_RISK_PRIORITY_H */
