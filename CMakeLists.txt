cmake_minimum_required(VERSION 3.22)

# Make sure VSCode and IntelliSense finds its necessary data
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


include(FetchContent)
Set(FETCHCONTENT_QUIET FALSE)


# External repositories we need 
FetchContent_Declare(liboqs
    GIT_REPOSITORY          https://github.com/Frauschi/liboqs.git
    GIT_TAG                 origin/main
    GIT_PROGRESS            TRUE
    USES_TERMINAL_DOWNLOAD  TRUE
)

FetchContent_Declare(wolfssl
    GIT_REPOSITORY          https://github.com/Frauschi/wolfssl.git
    GIT_TAG                 origin/development
    GIT_PROGRESS            TRUE
    USES_TERMINAL_DOWNLOAD  TRUE
)

project(kritis3m_pki)

# Liboqs configuration
set(OQS_DIST_BUILD  OFF)
set(OQS_BUILD_ONLY_LIB ON)
set(OQS_USE_OPENSSL OFF)
set(OQS_ENABLE_KEM_BIKE OFF)
set(OQS_ENABLE_KEM_FRODOKEM OFF)
set(OQS_ENABLE_KEM_NTRUPRIME OFF)
set(OQS_ENABLE_KEM_CLASSIC_MCELIECE OFF)
set(OQS_ENABLE_KEM_HQC OFF)

# WolfSSL configuration
set(WOLFSSL_USER_SETTINGS ON)
set(WOLFSSL_EXAMPLES OFF)
set(WOLFSSL_CRYPT_TESTS OFF)
set(BUILD_SHARED_LIBS OFF)
set(WOLFSSL_OQS OFF)
set(WOLFSSL_BUILD_OUT_OF_TREE ON)

FetchContent_MakeAvailable(liboqs wolfssl)

# In order for WolfSSL to find the 'user_settings.h' file, we have to
# provide the directory where it is located.
target_include_directories(wolfssl PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/config/wolfssl>)

# Provide the liboqs headers (generated during build) for WolfSSL
get_target_property(OQS_BINARY_DIR oqs BINARY_DIR)
target_include_directories(wolfssl PUBLIC $<BUILD_INTERFACE:${OQS_BINARY_DIR}/../include>)

# Link liboqs to WolfSSL
target_link_libraries(wolfssl PRIVATE oqs)


# Define a library for the common PKI functions
add_library(kritis3m_pki_common STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/common.c
)

target_include_directories(kritis3m_pki_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/config
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(kritis3m_pki_common PUBLIC wolfssl)


# Define the executables
add_executable(create_certificate
    ${CMAKE_CURRENT_SOURCE_DIR}/src/create_certificate.c
)
target_link_libraries(create_certificate PUBLIC kritis3m_pki_common)


