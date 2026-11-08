/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/risk/priority.h"

#include "pqscan/risk/risk.h"

#include <stdbool.h>
#include <stddef.h>

enum {
    REVIEW_SCORE = 10,
    QUANTUM_BASE_SCORE = 50,
    DEPRECATED_POINTS = 10,
    DISALLOWED_POINTS = 20,
    EXPOSURE_THRESHOLD_POINTS = 10, /* What X + Y = Q scores: on the edge, not yet exposed. */
    EXPOSURE_MAX_POINTS = 29,
};

/* Nothing that can wait for a quantum computer may outrank what is broken today. */
_Static_assert(QUANTUM_BASE_SCORE + DISALLOWED_POINTS + EXPOSURE_MAX_POINTS < PRIORITY_MAX_SCORE,
               "a quantum-vulnerable finding must score below a classically weak one");

priority priority_none(void) {
    const priority none = {0, NULL, {false, 0, 0, 0, 0, IR8547_ACCEPTABLE}};
    return none;
}

static ir8547_status ir8547_status_in(int year) {
    if (year > IR8547_DISALLOWED_AFTER) {
        return IR8547_DISALLOWED;
    }
    return (year > IR8547_DEPRECATED_AFTER) ? IR8547_DEPRECATED : IR8547_ACCEPTABLE;
}

static quantum_timeline timeline_of(const data_lifetime *lifetime, const priority_basis *basis) {
    const int end_year = basis->as_of_year + lifetime->migration_years;
    const quantum_timeline timeline = {
        true,
        lifetime->secrecy_years,
        lifetime->migration_years,
        basis->quantum_year - basis->as_of_year,
        end_year,
        ir8547_status_in(end_year),
    };
    return timeline;
}

static int clamp(int value, int low, int high) {
    if (value < low) {
        return low;
    }
    return (value > high) ? high : value;
}

static unsigned deadline_points(ir8547_status status) {
    switch (status) {
    case IR8547_ACCEPTABLE:
        return 0;
    case IR8547_DEPRECATED:
        return DEPRECATED_POINTS;
    case IR8547_DISALLOWED:
        return DISALLOWED_POINTS;
    }
    return 0;
}

/* Mosca's margin X + Y - Q, in years, shifted so that the edge of exposure scores in the
 * middle: data that is safe by a wide margin scores nothing, and every year past the edge
 * counts up to the cap. */
static unsigned exposure_points(const quantum_timeline *timeline) {
    const int margin =
        timeline->secrecy_years + timeline->migration_years - timeline->years_to_quantum;
    return (unsigned)clamp(EXPOSURE_THRESHOLD_POINTS + margin, 0, EXPOSURE_MAX_POINTS);
}

static unsigned quantum_score(const quantum_timeline *timeline) {
    return QUANTUM_BASE_SCORE + deadline_points(timeline->status) + exposure_points(timeline);
}

priority priority_assess(risk_level risk, const data_lifetime *lifetime,
                         const priority_basis *basis) {
    priority result = priority_none();
    result.component = lifetime->component;
    switch (risk) {
    case RISK_OK:
        break;
    case RISK_REVIEW:
        result.score = REVIEW_SCORE;
        break;
    case RISK_QUANTUM_VULNERABLE:
        result.timeline = timeline_of(lifetime, basis);
        result.score = quantum_score(&result.timeline);
        break;
    case RISK_CLASSICALLY_WEAK:
        result.score = PRIORITY_MAX_SCORE;
        break;
    }
    return result;
}

bool quantum_timeline_exposed(const quantum_timeline *timeline) {
    return timeline->applies &&
           timeline->secrecy_years + timeline->migration_years > timeline->years_to_quantum;
}

const char *ir8547_status_name(ir8547_status status) {
    switch (status) {
    case IR8547_ACCEPTABLE:
        return "acceptable";
    case IR8547_DEPRECATED:
        return "deprecated";
    case IR8547_DISALLOWED:
        return "disallowed";
    }
    return "unknown";
}
