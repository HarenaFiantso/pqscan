# SPDX-License-Identifier: Apache-2.0
include(FetchContent)

option(PQSCAN_CHECK_REPORT_SCHEMAS
    "Validate reports against the CycloneDX and SARIF schemas (needs check-jsonschema)" OFF)

# Off by default because it is the only test that needs a tool beyond the compiler.
if(PQSCAN_CHECK_REPORT_SCHEMAS)
    find_program(PQSCAN_CHECK_JSONSCHEMA_PROGRAM check-jsonschema REQUIRED)

    pqscan_declare_github_archive(cyclonedx_specification
        REPOSITORY CycloneDX/specification TAG 1.6.1
        SHA256 653ae128c95299b44e1b8d82bc058f96b63f3cc0db7416b4642dcb4670aa1734
        SOURCE_SUBDIR none)
    pqscan_download(PQSCAN_SARIF_SCHEMA
        FILE sarif-schema-2.1.0.json
        SHA256 c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e
        URLS https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json)
    FetchContent_MakeAvailable(cyclonedx_specification)
endif()
