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

# When enabled, the CLI tools will be built as a self-contained executables with all
# dependencies included. When disabled, the tools dynamically load the dependencies
# at runtime.
option(KRITIS3M_PKI_TOOLS_SELF_CONTAINED "Build self-contained CLI tools" ON)

# When enabled, the compiled PKI libraries are installed, too. When disabled, only
# the executables are installed. Only relevant when building self-contained tools.
option(KRITIS3M_PKI_INSTALL_LIBRARIES "Install PKI libraries" OFF)

# When enabled, the WolfPKCS11 library is added as a dependency and compiled as a
# shared library. When disabled, the library is not included.
option(KRITIS3M_PKI_INCLUDE_WOLFPKCS11 "Include WolfPKCS11 library" OFF)


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
        -march=native
        -fomit-frame-pointer
        -fdata-sections
        -ffunction-sections
        # -Wl,--gc-sections
)

if (NOT MSVC)
        target_compile_options(kritis3m_pki PUBLIC
                -Wall
                -Wextra
                -Wpedantic
                -Werror
                # -Wa,--noexecstack
                -Wl,--gc-sections
        )
endif()

# Define the additional kritis3m_se_importer executable
add_executable(kritis3m_se_importer
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cli_common.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_se_importer.c
)
target_include_directories(kritis3m_se_importer PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_options(kritis3m_se_importer PUBLIC
        -march=native
        -fomit-frame-pointer
        -fdata-sections
        -ffunction-sections
        # -Wl,--gc-sections
)

if (NOT MSVC)
        target_compile_options(kritis3m_se_importer PUBLIC
                -Wall
                -Wextra
                -Wpedantic
                -Werror
                # -Wa,--noexecstack
                -Wl,--gc-sections
        )
endif()


# When building a self-contained tools, we need to build static libraries. Otherwise,
# we build shared libraries to save space and prevent multiple-definition problems.
if(KRITIS3M_PKI_TOOLS_SELF_CONTAINED)
        set(BUILD_SHARED_LIBS OFF)
        set(KRITIS3M_PKI_STANDALONE OFF)
else()
        set(BUILD_SHARED_LIBS ON)
        set(KRITIS3M_PKI_STANDALONE ON)
        set(KRITIS3M_PKI_INSTALL_LIBRARIES ON)
endif()


# When including WolfPKCS11, we need to build shared libraries. Otherwise, the shared
# object will not be able to find the symbols in the static WolfSSL library.
if(KRITIS3M_PKI_INCLUDE_WOLFPKCS11)
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
if(KRITIS3M_PKI_INSTALL_LIBRARIES)
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../library ${CMAKE_CURRENT_BINARY_DIR}/../library)
else()
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../library ${CMAKE_CURRENT_BINARY_DIR}/../library EXCLUDE_FROM_ALL)
endif()


if(KRITIS3M_PKI_INCLUDE_WOLFPKCS11)
        # Pull wolfPKCS11 as dependency when required
        FetchContent_Declare(wolfpkcs11
                GIT_REPOSITORY          git@github.com:Laboratory-for-Safe-and-Secure-Systems/wolfPKCS11.git
                GIT_TAG                 origin/development
                GIT_PROGRESS            TRUE
                USES_TERMINAL_DOWNLOAD  TRUE
        )

        # Actually add the external repositories to our project
        FetchContent_GetProperties(wolfpkcs11)
        if(NOT wolfpkcs11_POPULATED)
                FetchContent_Populate(wolfpkcs11)
                if(NOT KRITIS3M_PKI_TOOLS_SELF_CONTAINED)
                        add_subdirectory(${wolfpkcs11_SOURCE_DIR} ${wolfpkcs11_BINARY_DIR})
                else()
                        add_subdirectory(${wolfpkcs11_SOURCE_DIR} ${wolfpkcs11_BINARY_DIR} EXCLUDE_FROM_ALL)
                endif()
        endif()

        # Add executable to provision a wolfPKCS11 token
        add_executable(wolfpkcs11_provision
                ${CMAKE_CURRENT_SOURCE_DIR}/src/wolfpkcs11_provision.c
        )
        target_include_directories(wolfpkcs11_provision PUBLIC
                ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_compile_options(wolfpkcs11_provision PUBLIC
                -march=native
                -fomit-frame-pointer
                -fdata-sections
                -ffunction-sections
                # -Wl,--gc-sections
        )

        if (NOT MSVC)
                target_compile_options(wolfpkcs11_provision PUBLIC
                        -Wall
                        -Wextra
                        -Wpedantic
                        -Werror
                        # -Wa,--noexecstack
                        -Wl,--gc-sections
                )
        endif()

        # WolfPKCS11 needs WolfSSL
        target_link_libraries(wolfpkcs11 PRIVATE wolfssl)

        # Add the wolfPKCS11 library as a dependency
        add_dependencies(wolfpkcs11_provision wolfpkcs11)
        target_link_libraries(wolfpkcs11_provision PRIVATE kritis3m_applications_common)
        target_link_libraries(wolfpkcs11_provision PRIVATE wolfssl)

        # Install the wolfPKCS11 provisioning tool
        install(TARGETS wolfpkcs11_provision DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()


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

