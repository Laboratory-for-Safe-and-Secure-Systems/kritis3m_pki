cmake_minimum_required(VERSION 3.22)

# Make sure VSCode and IntelliSense finds its necessary data
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


include(FetchContent)
Set(FETCHCONTENT_QUIET FALSE)

set(TARGET kritis3m_pki)

# External repositories we need
FetchContent_Declare(kritis3m_applications
    GIT_REPOSITORY          git@github.com:Laboratory-for-Safe-and-Secure-Systems/kritis3m_applications.git
    GIT_TAG                 origin/main
    GIT_PROGRESS            TRUE
)


# Add the library
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../library ${CMAKE_CURRENT_BINARY_DIR}/../library)

# Define the complete generate_certificate executable
add_executable(${TARGET}
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cli_common.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/create_certificate.c
)

target_include_directories(${TARGET} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_options(${TARGET} PUBLIC
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

# Actually add the external repositories to our project
set(ENABLE_TCP_ECHO_SERVER OFF)
set(ENABLE_TCP_CLIENT_STDIN_BRIDGE OFF)
set(ENABLE_TLS_PROXY OFF)
FetchContent_GetProperties(kritis3m_applications)
if(NOT kritis3m_applications_POPULATED)
  FetchContent_Populate(kritis3m_applications)
  add_subdirectory(${kritis3m_applications_SOURCE_DIR} ${kritis3m_applications_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

# Link the PKI libraries
target_link_libraries(${TARGET} PUBLIC pki_client)
target_link_libraries(${TARGET} PUBLIC pki_server)

# Install the executable
install(TARGETS kritis3m_pki DESTINATION bin)

