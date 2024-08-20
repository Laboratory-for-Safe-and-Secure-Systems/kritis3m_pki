cmake_minimum_required(VERSION 3.22)

include(GNUInstallDirs)
include(FetchContent)
set(FETCHCONTENT_QUIET FALSE)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


# Options

# When enabled, the CLI tools will be built as a self-contained executables with all
# dependencies included. When disabled, the tools dynamically load the dependencies
# at runtime.
option(KRITIS3M_PKI_TOOLS_SELF_CONTAINED "Build self-contained CLI tools" ON)


# Define the main kritis3m_pki executable
add_executable(kritis3m_pki
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cli_common.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_pki_cli_parsing.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_pki.c
)
target_include_directories(kritis3m_pki PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_options(kritis3m_pki PUBLIC
        -Wall
        -Wextra
        -Wpedantic
        -Werror
        -march=native
        -Wa,--noexecstack
        -fomit-frame-pointer
        -fdata-sections
        -ffunction-sections
        -Wl,--gc-sections
)

# Define the additional kritis3m_se_importer executable
add_executable(kritis3m_se_importer
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cli_common.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_se_importer.c
)
target_include_directories(kritis3m_se_importer PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_options(kritis3m_se_importer PUBLIC
        -Wall
        -Wextra
        -Wpedantic
        -Werror
        -march=native
        -Wa,--noexecstack
        -fomit-frame-pointer
        -fdata-sections
        -ffunction-sections
        -Wl,--gc-sections
)


# When building a self-contained tools, we need to build static libraries. Otherwise,
# we build shared libraries to save space and prevent multiple-definition problems.
if(KRITIS3M_PKI_TOOLS_SELF_CONTAINED)
        set(BUILD_SHARED_LIBS OFF)
else()
        set(BUILD_SHARED_LIBS ON)
endif()


# Add the KRITIS3M_APPLICATION dependency
FetchContent_Declare(kritis3m_applications
        GIT_REPOSITORY          git@github.com:Laboratory-for-Safe-and-Secure-Systems/kritis3m_applications.git
        GIT_TAG                 origin/main
        GIT_PROGRESS            TRUE
)
set(ENABLE_TCP_ECHO_SERVER OFF)
set(ENABLE_TCP_CLIENT_STDIN_BRIDGE OFF)
set(ENABLE_TLS_PROXY OFF)
FetchContent_GetProperties(kritis3m_applications)
if(NOT kritis3m_applications_POPULATED)
        FetchContent_Populate(kritis3m_applications)
        add_subdirectory(${kritis3m_applications_SOURCE_DIR} ${kritis3m_applications_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()


# Add the PKI libraries
set(KRITIS3M_PKI_STANDALONE NOT ${KRITIS3M_PKI_TOOLS_SELF_CONTAINED})
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../library ${CMAKE_CURRENT_BINARY_DIR}/../library)


# Link the KRITIS3M_APPLICATIONS targets
target_link_libraries(kritis3m_pki PRIVATE kritis3m_applications_common)
target_link_libraries(kritis3m_se_importer PRIVATE kritis3m_applications_common)


# Link the PKI libraries
target_link_libraries(kritis3m_pki PUBLIC kritis3m_pki_client)
target_link_libraries(kritis3m_pki PUBLIC kritis3m_pki_server)
target_link_libraries(kritis3m_se_importer PUBLIC kritis3m_pki_client)


# Install the executables
install(TARGETS kritis3m_pki DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS kritis3m_se_importer DESTINATION ${CMAKE_INSTALL_BINDIR})

