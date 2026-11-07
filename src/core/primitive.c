/* SPDX-License-Identifier: Apache-2.0 */
#include "pqscan/core/primitive.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static const crypto_primitive ALL_PRIMITIVES[] = {
    PRIMITIVE_UNSPECIFIED, PRIMITIVE_SIGNATURE, PRIMITIVE_KEY_EXCHANGE,
    PRIMITIVE_ENCRYPTION,  PRIMITIVE_HASH,
};

const char *crypto_primitive_name(crypto_primitive primitive) {
    switch (primitive) {
    case PRIMITIVE_UNSPECIFIED:
        return "unspecified";
    case PRIMITIVE_SIGNATURE:
        return "signature";
    case PRIMITIVE_KEY_EXCHANGE:
        return "key_exchange";
    case PRIMITIVE_ENCRYPTION:
        return "encryption";
    case PRIMITIVE_HASH:
        return "hash";
    }
    return "unknown";
}

bool crypto_primitive_parse(const char *name, crypto_primitive *out) {
    for (size_t i = 0; i < sizeof(ALL_PRIMITIVES) / sizeof(ALL_PRIMITIVES[0]); i++) {
        if (strcmp(name, crypto_primitive_name(ALL_PRIMITIVES[i])) == 0) {
            *out = ALL_PRIMITIVES[i];
            return true;
        }
    }
    return false;
}
