cmake_minimum_required(VERSION 3.22)

# Make sure VSCode and IntelliSense finds its necessary data
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


# Add the library
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../library ${CMAKE_CURRENT_BINARY_DIR}/../library)

# Define the complete generate_certificate executable
add_executable(kritis3m_pki
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cli_common.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/create_certificate.c
)

target_include_directories(kritis3m_pki PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(kritis3m_pki PUBLIC pki_client)
target_link_libraries(kritis3m_pki PUBLIC pki_server)

# Install the executable
install(TARGETS kritis3m_pki DESTINATION bin)

