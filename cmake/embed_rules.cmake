# SPDX-License-Identifier: Apache-2.0

# Writes a C file holding the bytes of a rule file, so the binary needs no file at run time.
# C11 has no #embed. This runs at configure time, because clang-tidy and cppcheck read the
# compile database without building, and every file it lists has to exist by then.
function(pqscan_embed_rules input output)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${input}")
    file(READ "${input}" bytes HEX)
    string(REGEX REPLACE "(..)" "0x\\1," bytes "${bytes}")
    # file(CONFIGURE) leaves an unchanged file alone, so a new configure recompiles nothing.
    file(CONFIGURE OUTPUT "${output}" @ONLY CONTENT
"/* SPDX-License-Identifier: Apache-2.0 */
/* Generated from rules/default.json. Do not edit. */
#include \"pqscan/rules/default_rules.h\"

#include \"pqscan/rules/rule_loader.h\"

static const unsigned char DEFAULT_RULES[] = {@bytes@};

rule_source default_rules_source(void) {
    const rule_source source = {(const char *)DEFAULT_RULES, sizeof(DEFAULT_RULES)};
    return source;
}
")
endfunction()
