# SPDX-License-Identifier: Apache-2.0
#
# Writes a C file holding the bytes of a rule file, so the binary needs no file at run time.
# C11 has no #embed. Inputs: INPUT and OUTPUT, both paths.

file(READ "${INPUT}" bytes HEX)
string(REGEX REPLACE "(..)" "0x\\1," bytes "${bytes}")

file(WRITE "${OUTPUT}" "/* SPDX-License-Identifier: Apache-2.0 */
/* Generated from rules/default.json. Do not edit. */
#include \"pqscan/rules/default_rules.h\"

#include \"pqscan/rules/rule_loader.h\"

static const unsigned char DEFAULT_RULES[] = {${bytes}};

rule_source default_rules_source(void) {
    const rule_source source = {(const char *)DEFAULT_RULES, sizeof(DEFAULT_RULES)};
    return source;
}
")
