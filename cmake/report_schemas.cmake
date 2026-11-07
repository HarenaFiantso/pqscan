# SPDX-License-Identifier: Apache-2.0
include(FetchContent)

option(PQSCAN_CHECK_REPORT_SCHEMAS
    "Validate reports against the CycloneDX and SARIF schemas (needs check-jsonschema)" OFF)

# Off by default because it is the only test that needs a tool beyond the compiler.
if(PQSCAN_CHECK_REPORT_SCHEMAS)
    find_program(PQSCAN_CHECK_JSONSCHEMA_PROGRAM check-jsonschema REQUIRED)

    FetchContent_Declare(cyclonedx_specification
        URL https://github.com/CycloneDX/specification/archive/refs/tags/1.6.1.tar.gz
        URL_HASH SHA256=653ae128c95299b44e1b8d82bc058f96b63f3cc0db7416b4642dcb4670aa1734
        DOWNLOAD_DIR "${PQSCAN_DOWNLOAD_DIR}"
        SOURCE_SUBDIR none)
    FetchContent_Declare(sarif_schema
        URL https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
        URL_HASH SHA256=c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e
        DOWNLOAD_DIR "${PQSCAN_DOWNLOAD_DIR}"
        DOWNLOAD_NO_EXTRACT TRUE
        SOURCE_SUBDIR none)
    FetchContent_MakeAvailable(cyclonedx_specification sarif_schema)
endif()
