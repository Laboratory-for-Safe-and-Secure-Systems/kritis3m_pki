cmake_minimum_required(VERSION 3.22)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


# Options

# Select between shared or static libraries
option(BUILD_SHARED_LIBS "Build shared libraries (.so) instead of static ones (.a)" ON)

# When this option is enabled, the KRITIS3M_wolfssl dependency will be built as standalone
# library to be installed system-wide. When disabled, the library will be built as a library
# only to be linked against a wrapping application.
option(KRITIS3M_PKI_STANDALONE "Use standalone WolfSSL" ON)

# Use an externally installed WolfSSL library. If disabled, WolfSSL will be built.
option(KRITIS3M_PKI_EXTERNAL_WOLFSSL "Use external WolfSSL library" OFF)


if(KRITIS3M_PKI_EXTERNAL_WOLFSSL)

# Search for system-wide installed WolfSSL
find_package(liboqs REQUIRED)
find_package(wolfssl REQUIRED)

else(KRITIS3M_PKI_EXTERNAL_WOLFSSL)

# External repositories we need
include(FetchContent)
Set(FETCHCONTENT_QUIET FALSE)
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
add_library(pki_common
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_pki_common.c
)

target_include_directories(pki_common PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_include_directories(pki_common PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include
)

target_link_libraries(pki_common PUBLIC wolfssl)


# Define the client library
add_library(pki_client
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_pki_client.c
)

target_include_directories(pki_client PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_include_directories(pki_client PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include
)

target_link_libraries(pki_client PUBLIC pki_common)


# Define the server library
add_library(pki_server
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_pki_server.c
)

target_include_directories(pki_server PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_include_directories(pki_server PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include
)

target_link_libraries(pki_server PUBLIC pki_common)


# Create combined static libraries that include all dependencies for a PKI client or server
if (NOT BUILD_SHARED_LIBS)

set(LIBNAME_SERVER "libkritis3m_pki_server.a")
set(LIBNAME_CLIENT "libkritis3m_pki_client.a")

set(WOLFSSL_TARGET_NAME "wolfssl")
set(LIBOQS_TARGET_NAME "oqs")

if(KRITIS3M_PKI_EXTERNAL_WOLFSSL)
        set(WOLFSSL_TARGET_NAME "wolfssl::wolfssl")
        set(LIBOQS_TARGET_NAME "OQS::oqs")
endif(KRITIS3M_PKI_EXTERNAL_WOLFSSL)

set(create_combined_lib_script_common
        "addlib $<TARGET_FILE:pki_common>\naddlib $<TARGET_FILE:${WOLFSSL_TARGET_NAME}>\naddlib $<TARGET_FILE:${LIBOQS_TARGET_NAME}>\nsave\nend\n"
)

set(create_combined_lib_script_server
        "create ${LIBNAME_SERVER}\naddlib $<TARGET_FILE:pki_server>\n${create_combined_lib_script_common}"
)

set(create_combined_lib_script_client
        "create ${LIBNAME_CLIENT}\naddlib $<TARGET_FILE:pki_client>\n${create_combined_lib_script_common}"
)

file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/create_combined_lib_script_server.ar"
        CONTENT ${create_combined_lib_script_server}
        CONDITION 1
)

file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/create_combined_lib_script_client.ar"
        CONTENT ${create_combined_lib_script_client}
        CONDITION 1
)

add_custom_command(TARGET pki_server POST_BUILD
        DEPENDS pki_common wolfssl oqs
        COMMAND ${CMAKE_AR} -M < create_combined_lib_script_server.ar
        COMMENT "Creating combined static library ${LIBNAME_SERVER}"
)

add_custom_command(TARGET pki_client POST_BUILD
        DEPENDS pki_common wolfssl oqs
        COMMAND ${CMAKE_AR} -M < create_combined_lib_script_client.ar
        COMMENT "Creating combined static library ${LIBNAME_CLIENT}"
)

# Install the library files
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${LIBNAME_SERVER} TYPE LIB)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${LIBNAME_CLIENT} TYPE LIB)

endif(NOT BUILD_SHARED_LIBS)


# Install files
install(TARGETS pki_common EXPORT kritis3m_pki_common-export DESTINATION lib)
install(TARGETS pki_server EXPORT kritis3m_pki_server-export DESTINATION lib)
install(TARGETS pki_client EXPORT kritis3m_pki_client-export DESTINATION lib)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION include/kritis3m_pki)

# Install CMake configuration files
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/kritis3m_pki_server-config.cmake DESTINATION lib/cmake/kritis3m_pki_server)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/cmake/kritis3m_pki_client-config.cmake DESTINATION lib/cmake/kritis3m_pki_client)

install(EXPORT kritis3m_pki_common-export DESTINATION lib/cmake/kritis3m_pki_common FILE kritis3m_pki_common-export.cmake)
export(EXPORT kritis3m_pki_common-export FILE kritis3m_pki_server-common.cmake)

install(EXPORT kritis3m_pki_server-export DESTINATION lib/cmake/kritis3m_pki_server FILE kritis3m_pki_server-export.cmake)
export(EXPORT kritis3m_pki_server-export FILE kritis3m_pki_server-export.cmake)

install(EXPORT kritis3m_pki_client-export DESTINATION lib/cmake/kritis3m_pki_client FILE kritis3m_pki_client-export.cmake)
export(EXPORT kritis3m_pki_client-export FILE kritis3m_pki_client-export.cmake)


