cmake_minimum_required(VERSION 3.22)

include(GNUInstallDirs)
include(FetchContent)
set(FETCHCONTENT_QUIET FALSE)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Necessary to allow FetchContent_Populate
if(POLICY CMP0169)
        cmake_policy(SET CMP0169 OLD)
endif()


# Options

# Select between shared or static libraries
option(BUILD_SHARED_LIBS "Build shared libraries (.so) instead of static ones (.a)" ON)

# When this option is enabled, the KRITIS3M_wolfssl dependency will be built as standalone
# library to be installed system-wide. When disabled, the library will be built as a library
# only to be linked against a wrapping application.
option(KRITIS3M_PKI_STANDALONE "Use standalone WolfSSL" ON)

# Use an externally installed WolfSSL library. If disabled, WolfSSL will be built.
option(KRITIS3M_PKI_EXTERNAL_WOLFSSL "Use external WolfSSL library" OFF)

# Create a combined static library that includes all dependencies
option(KRITIS3M_PKI_COMBINED_STATIC_LIB "Create a combined static library" OFF)


# Make sure all libraries are installed in the lib directory (not lib64)
set(CMAKE_INSTALL_LIBDIR "lib")


# Pull in WolfSSL as dependency (either as an external library or as a subproject)
if(KRITIS3M_PKI_EXTERNAL_WOLFSSL)
        # Search for system-wide installed WolfSSL
        find_package(liboqs REQUIRED)
        find_package(wolfssl REQUIRED)

else(KRITIS3M_PKI_EXTERNAL_WOLFSSL)
        # Pull in kritis3m_wolfssl as a dependency
        FetchContent_Declare(kritis3m_wolfssl
                GIT_REPOSITORY          git@github.com:Laboratory-for-Safe-and-Secure-Systems/kritis3m_wolfssl.git
                GIT_TAG                 origin/main
                GIT_PROGRESS            TRUE
                USES_TERMINAL_DOWNLOAD  TRUE
        )

        # Configuration
        set(KRITIS3M_WOLFSSL_STANDALONE ${KRITIS3M_PKI_STANDALONE})

        # Actually add the external repositories to our project
        FetchContent_GetProperties(kritis3m_wolfssl)
        if(NOT kritis3m_wolfssl_POPULATED)
                FetchContent_Populate(kritis3m_wolfssl)
                if(KRITIS3M_PKI_STANDALONE)
                        add_subdirectory(${kritis3m_wolfssl_SOURCE_DIR} ${kritis3m_wolfssl_BINARY_DIR})
                else()
                        add_subdirectory(${kritis3m_wolfssl_SOURCE_DIR} ${kritis3m_wolfssl_BINARY_DIR} EXCLUDE_FROM_ALL)
                endif()
        endif()
endif(KRITIS3M_PKI_EXTERNAL_WOLFSSL)


# Define the common library
add_library(kritis3m_pki_common
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_pki_common.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_pki_logging.c
)
target_include_directories(kritis3m_pki_common PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include/kritis3m_pki>
)
target_include_directories(kritis3m_pki_common PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include
)
target_link_libraries(kritis3m_pki_common PUBLIC wolfssl)
target_compile_definitions(kritis3m_pki_common PRIVATE "BUILDING_KRITIS3M_PKI")
if(BUILD_SHARED_LIBS)
    target_compile_definitions(kritis3m_pki_common PUBLIC "BUILDING_KRITIS3M_PKI_SHARED")
endif()


# Define the client library
add_library(kritis3m_pki_client
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_pki_client.c
)
target_include_directories(kritis3m_pki_client PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include/kritis3m_pki>
)
target_include_directories(kritis3m_pki_client PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include
)
target_link_libraries(kritis3m_pki_client PUBLIC kritis3m_pki_common)
target_compile_definitions(kritis3m_pki_client PRIVATE "BUILDING_KRITIS3M_PKI")
if(BUILD_SHARED_LIBS)
    target_compile_definitions(kritis3m_pki_client PUBLIC "BUILDING_KRITIS3M_PKI_SHARED")
endif()


# Define the server library
add_library(kritis3m_pki_server
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_pki_server.c
)
target_include_directories(kritis3m_pki_server PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include/kritis3m_pki>
)
target_include_directories(kritis3m_pki_server PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include
)
target_link_libraries(kritis3m_pki_server PUBLIC kritis3m_pki_common)
target_compile_definitions(kritis3m_pki_server PRIVATE "BUILDING_KRITIS3M_PKI")
if(BUILD_SHARED_LIBS)
    target_compile_definitions(kritis3m_pki_server PUBLIC "BUILDING_KRITIS3M_PKI_SHARED")
endif()


# Install library and header files
install(TARGETS kritis3m_pki_common
        EXPORT kritis3m_pki_common-export
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(TARGETS kritis3m_pki_server
        EXPORT kritis3m_pki_server-export
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(TARGETS kritis3m_pki_client
        EXPORT kritis3m_pki_client-export
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/kritis3m_pki
)

# Install CMake configuration files so other CMake projects can find the libraries
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/kritis3m_pki_server-config.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kritis3m_pki_server
)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/kritis3m_pki_client-config.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kritis3m_pki_client
)

install(EXPORT kritis3m_pki_common-export
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kritis3m_pki_common
        FILE kritis3m_pki_common-export.cmake
)
export(EXPORT kritis3m_pki_common-export
       FILE kritis3m_pki_common-export.cmake
)

install(EXPORT kritis3m_pki_server-export
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kritis3m_pki_server
        FILE kritis3m_pki_server-export.cmake
)
export(EXPORT kritis3m_pki_server-export
       FILE kritis3m_pki_server-export.cmake
)

install(EXPORT kritis3m_pki_client-export
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kritis3m_pki_client
        FILE kritis3m_pki_client-export.cmake
)
export(EXPORT kritis3m_pki_client-export
       FILE kritis3m_pki_client-export.cmake
)

# Generate pkg-config files
set(LIBRARY_NAME "kritis3m_pki_server")
set(LIBRARY_ROLE "server")
configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/kritis3m_pki.pc.in
        ${CMAKE_CURRENT_BINARY_DIR}/kritis3m_pki_server.pc
        @ONLY
)
set(LIBRARY_NAME "kritis3m_pki_client")
set(LIBRARY_ROLE "client")
configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/kritis3m_pki.pc.in
        ${CMAKE_CURRENT_BINARY_DIR}/kritis3m_pki_client.pc
        @ONLY
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/kritis3m_pki_server.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/kritis3m_pki_client.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)


# Create combined static libraries that include all dependencies for a PKI client or server
if (NOT BUILD_SHARED_LIBS AND KRITIS3M_PKI_COMBINED_STATIC_LIB)
        set(LIBNAME_SERVER "libkritis3m_pki_server_full.a")
        set(LIBNAME_CLIENT "libkritis3m_pki_client_full.a")
        set(WOLFSSL_TARGET_NAME "wolfssl")
        set(LIBOQS_TARGET_NAME "oqs")

        # When using external WolfSSL, we need to use the imported targets
        # which contain a CMake namespace prefix
        if(KRITIS3M_PKI_EXTERNAL_WOLFSSL)
                set(WOLFSSL_TARGET_NAME "wolfssl::wolfssl")
                set(LIBOQS_TARGET_NAME "OQS::oqs")
        endif(KRITIS3M_PKI_EXTERNAL_WOLFSSL)

        string(CONCAT create_combined_lib_script_common
                "addlib $<TARGET_FILE:kritis3m_pki_common>\n"
                "addlib $<TARGET_FILE:${WOLFSSL_TARGET_NAME}>\n"
                "addlib $<TARGET_FILE:${LIBOQS_TARGET_NAME}>\n"
                "save\nend\n"
        )

        string(CONCAT create_combined_lib_script_server
                "create ${LIBNAME_SERVER}\n"
                "addlib $<TARGET_FILE:kritis3m_pki_server>\n"
                "${create_combined_lib_script_common}"
        )

        string(CONCAT create_combined_lib_script_client
                "create ${LIBNAME_CLIENT}\n"
                "addlib $<TARGET_FILE:kritis3m_pki_client>\n"
                "${create_combined_lib_script_common}"
        )

        file(GENERATE OUTPUT
                "${CMAKE_CURRENT_BINARY_DIR}/create_combined_lib_script_server.ar"
                CONTENT ${create_combined_lib_script_server}
                CONDITION 1
        )

        file(GENERATE OUTPUT
                "${CMAKE_CURRENT_BINARY_DIR}/create_combined_lib_script_client.ar"
                CONTENT ${create_combined_lib_script_client}
                CONDITION 1
        )

        add_custom_command(TARGET kritis3m_pki_server POST_BUILD
                COMMAND ${CMAKE_AR} -M < create_combined_lib_script_server.ar
                COMMENT "Creating combined static library ${LIBNAME_SERVER}"
        )

        add_custom_command(TARGET kritis3m_pki_client POST_BUILD
                COMMAND ${CMAKE_AR} -M < create_combined_lib_script_client.ar
                COMMENT "Creating combined static library ${LIBNAME_CLIENT}"
        )

        # Install the library files
        install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${LIBNAME_SERVER} TYPE LIB)
        install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${LIBNAME_CLIENT} TYPE LIB)
endif()
