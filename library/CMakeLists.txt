cmake_minimum_required(VERSION 3.22)

# Make sure VSCode and IntelliSense finds its necessary data
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


include(FetchContent)
Set(FETCHCONTENT_QUIET FALSE)

# External repositories we need
FetchContent_Declare(liboqs
    GIT_REPOSITORY          https://github.com/open-quantum-safe/liboqs.git
    GIT_TAG                 origin/main
    GIT_PROGRESS            TRUE
    USES_TERMINAL_DOWNLOAD  TRUE
)

FetchContent_Declare(wolfssl
    GIT_REPOSITORY          https://github.com/Laboratory-for-Safe-and-Secure-Systems/wolfssl.git
    GIT_TAG                 origin/development
    GIT_PROGRESS            TRUE
    USES_TERMINAL_DOWNLOAD  TRUE
)


# Liboqs configuration
set(OQS_DIST_BUILD  OFF)
set(OQS_BUILD_ONLY_LIB ON)
set(OQS_USE_OPENSSL OFF)
set(OQS_ENABLE_KEM_BIKE OFF)
set(OQS_ENABLE_KEM_FRODOKEM OFF)
set(OQS_ENABLE_KEM_NTRUPRIME OFF)
set(OQS_ENABLE_KEM_CLASSIC_MCELIECE OFF)
set(OQS_ENABLE_KEM_HQC OFF)
set(OQS_ENABLE_KEM_ML_KEM OFF)
set(OQS_ENABLE_SIG_SPHINCS OFF)
set(OQS_ENABLE_SIG_ML_DSA OFF)

# WolfSSL configuration
set(WOLFSSL_USER_SETTINGS ON)
set(WOLFSSL_EXAMPLES OFF)
set(WOLFSSL_CRYPT_TESTS OFF)
set(BUILD_SHARED_LIBS OFF)
set(WOLFSSL_OQS OFF)
set(WOLFSSL_BUILD_OUT_OF_TREE ON)

# Actually add the external repositories to our project
FetchContent_GetProperties(liboqs)
if(NOT liboqs_POPULATED)
  FetchContent_Populate(liboqs)
  add_subdirectory(${liboqs_SOURCE_DIR} ${liboqs_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

FetchContent_GetProperties(wolfssl)
if(NOT wolfssl_POPULATED)
  FetchContent_Populate(wolfssl)
  add_subdirectory(${wolfssl_SOURCE_DIR} ${wolfssl_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

# In order for WolfSSL to find the 'user_settings.h' file, we have to
# provide the directory where it is located.
target_include_directories(wolfssl PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include/wolfssl>)

# Provide the liboqs headers (generated during build) for WolfSSL
get_target_property(OQS_BINARY_DIR oqs BINARY_DIR)
target_include_directories(wolfssl PUBLIC $<BUILD_INTERFACE:${OQS_BINARY_DIR}/../include>)

# Link liboqs to WolfSSL
target_link_libraries(wolfssl PRIVATE oqs)


# Define the common library
add_library(pki_common STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_pki_common.c
)

target_include_directories(pki_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(pki_common PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include
)

target_link_libraries(pki_common PUBLIC wolfssl)


# Define the client library
add_library(pki_client STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_pki_client.c
)

target_include_directories(pki_client PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(pki_client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include
)

target_link_libraries(pki_client PRIVATE pki_common)


# Define the server library
add_library(pki_server STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kritis3m_pki_server.c
)

target_include_directories(pki_server PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(pki_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/priv_include
)

target_link_libraries(pki_server PRIVATE pki_common)


# Create combined static libraries that include all dependencies for a PKI client or server
set(LIBNAME_SERVER "libkritis3m_pki_server.a")
set(LIBNAME_CLIENT "libkritis3m_pki_client.a")

set(create_combined_lib_script_common
        "addlib $<TARGET_FILE:pki_common>\naddlib $<TARGET_FILE:wolfssl>\naddlib $<TARGET_FILE:oqs>\nsave\nend\n"
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

# Install header files
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION include/kritis3m_pki)