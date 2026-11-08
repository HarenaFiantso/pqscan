# SPDX-License-Identifier: Apache-2.0
include(GNUInstallDirs)

install(TARGETS pqscan RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${PROJECT_SOURCE_DIR}/man/pqscan.1" DESTINATION "${CMAKE_INSTALL_MANDIR}/man1")
# The binary has the rules built in. This copy is where a rules file for --rules starts from.
install(FILES "${PROJECT_SOURCE_DIR}/rules/default.json" DESTINATION "${CMAKE_INSTALL_DATADIR}/pqscan")
install(FILES
        "${PROJECT_SOURCE_DIR}/CHANGELOG.md"
        "${PROJECT_SOURCE_DIR}/LICENSE"
        "${PROJECT_SOURCE_DIR}/NOTICE"
        "${PROJECT_SOURCE_DIR}/README.md"
    DESTINATION "${CMAKE_INSTALL_DOCDIR}")

# The binary holds a copy of each of these, and the MIT license asks for its text to come with
# every copy. OpenSSL's license is Apache-2.0, the same text as LICENSE.
foreach(dependency IN ITEMS tree_sitter tree_sitter_c tree_sitter_cpp cjson)
    string(REPLACE "_" "-" name "${dependency}")
    install(FILES "${${dependency}_SOURCE_DIR}/LICENSE"
        DESTINATION "${CMAKE_INSTALL_DOCDIR}/licenses"
        RENAME "${name}.txt")
endforeach()
