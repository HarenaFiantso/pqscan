/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/scan/config_list.h"

#include "pqscan/core/status.h"
#include "pqscan/rules/rule_set.h"
#include "pqscan/scan/config_lexer.h"

#include <stdbool.h>
#include <stddef.h>

/* The longest name in the rules is two parts, as DES-CBC3. Bounding the run keeps a hostile
 * entry of a million parts linear instead of quadratic. */
enum { MAX_PARTS_PER_NAME = 4 };

/* A run of the word, by offset. */
typedef struct span {
    size_t start;
    size_t end;
} span;

typedef struct list_walk {
    const config_list_scan *scan;
    const config_word *word;
    size_t counted_to; /* Newlines before this offset are already in line. */
    size_t line;
} list_walk;

/* Matches come in order, so each newline is counted once. */
static size_t line_at(list_walk *walk, size_t offset) {
    for (; walk->counted_to < offset; walk->counted_to++) {
        walk->line += (walk->word->text[walk->counted_to] == '\n') ? 1 : 0;
    }
    return walk->line;
}

static char byte_at(const list_walk *walk, size_t offset) { return walk->word->text[offset]; }

static const crypto_rule *find_name(const list_walk *walk, span name) {
    if (name.end <= name.start) {
        return NULL;
    }
    return rule_set_find_config_token(walk->scan->rules, walk->word->text + name.start,
                                      name.end - name.start);
}

static pqscan_status report(list_walk *walk, const crypto_rule *rule, size_t offset) {
    const config_match match = {rule, line_at(walk, offset)};
    return walk->scan->visit(&match, walk->scan->context);
}

static pqscan_status match_whole(list_walk *walk, span name) {
    const crypto_rule *rule = find_name(walk, name);
    return (rule != NULL) ? report(walk, rule, name.start) : PQSCAN_OK;
}

static bool is_entry_separator(char byte) {
    return byte == ':' || byte == ',' || byte == '/' || byte == ' ' || byte == '\t' ||
           byte == '\r' || byte == '\n';
}

static bool is_part_separator(char byte) { return byte == '-' || byte == '+'; }

/* Fills ends with where each of the next parts ends, and returns how many there are. */
static size_t find_part_ends(const list_walk *walk, span range, size_t ends[MAX_PARTS_PER_NAME]) {
    size_t count = 0;
    size_t pos = range.start;
    while (count < MAX_PARTS_PER_NAME) {
        while (pos < range.end && !is_part_separator(byte_at(walk, pos))) {
            pos++;
        }
        ends[count++] = pos;
        if (pos == range.end) {
            break;
        }
        pos++;
    }
    return count;
}

/* Reports the longest run of parts at the start of range that a rule names. Returns where
 * that run ends, or where the first part ends when no run is named. */
static size_t longest_known_run(list_walk *walk, span range, pqscan_status *status) {
    size_t ends[MAX_PARTS_PER_NAME];
    const size_t count = find_part_ends(walk, range, ends);
    for (size_t parts = count; parts > 0; parts--) {
        const span run = {range.start, ends[parts - 1]};
        const crypto_rule *rule = find_name(walk, run);
        if (rule != NULL) {
            *status = report(walk, rule, range.start);
            return run.end;
        }
    }
    *status = PQSCAN_OK;
    return ends[0];
}

static pqscan_status match_parts(list_walk *walk, span entry) {
    size_t pos = entry.start;
    while (pos < entry.end) {
        pqscan_status status = PQSCAN_OK;
        const span rest = {pos, entry.end};
        const size_t end = longest_known_run(walk, rest, &status);
        if (status != PQSCAN_OK) {
            return status;
        }
        pos = (end < entry.end) ? end + 1 : entry.end;
    }
    return PQSCAN_OK;
}

static bool takes_away(char first) { return first == '!' || first == '-' || first == '@'; }

static bool only_reorders(char first) { return first == '+' || first == '?' || first == '*'; }

static pqscan_status match_openssl_entry(list_walk *walk, span entry) {
    if (takes_away(byte_at(walk, entry.start))) {
        return PQSCAN_OK;
    }
    while (entry.start < entry.end && only_reorders(byte_at(walk, entry.start))) {
        entry.start++;
    }
    return match_parts(walk, entry);
}

/* How a list splits into entries, and what to do with each. */
typedef struct entry_splitter {
    bool (*is_separator)(char byte);
    pqscan_status (*match)(list_walk *walk, span entry);
} entry_splitter;

/* Calls match for each run between separators, in order. */
static pqscan_status match_entries(list_walk *walk, size_t start, const entry_splitter *splitter) {
    const size_t len = walk->word->len;
    size_t pos = start;
    while (pos < len) {
        if (splitter->is_separator(byte_at(walk, pos))) {
            pos++;
            continue;
        }
        span entry = {pos, pos};
        while (entry.end < len && !splitter->is_separator(byte_at(walk, entry.end))) {
            entry.end++;
        }
        const pqscan_status status = splitter->match(walk, entry);
        if (status != PQSCAN_OK) {
            return status;
        }
        pos = entry.end;
    }
    return PQSCAN_OK;
}

static bool is_ssh_separator(char byte) { return byte == ','; }

static pqscan_status match_ssh(list_walk *walk) {
    if (walk->word->len == 0) {
        return PQSCAN_OK;
    }
    const char first = byte_at(walk, 0);
    if (first == '-') {
        return PQSCAN_OK;
    }
    const size_t start = (first == '+' || first == '^') ? 1 : 0;
    const entry_splitter splitter = {is_ssh_separator, match_whole};
    return match_entries(walk, start, &splitter);
}

pqscan_status config_list_match(const config_list_scan *scan, const config_word *word) {
    list_walk walk = {scan, word, 0, word->line};
    switch (scan->syntax) {
    case CONFIG_LIST_OPENSSL: {
        const entry_splitter splitter = {is_entry_separator, match_openssl_entry};
        return match_entries(&walk, 0, &splitter);
    }
    case CONFIG_LIST_SSH:
        return match_ssh(&walk);
    case CONFIG_LIST_SINGLE: {
        const span whole = {0, word->len};
        return match_whole(&walk, whole);
    }
    }
    return PQSCAN_OK;
}
