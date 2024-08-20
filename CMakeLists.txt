cmake_minimum_required(VERSION 3.22)
project(kritis3m_pki)


# Options

# Select between only building the PKI library or also the CLI tools
option(KRITIS3M_PKI_LIBRARY_ONLY "Build only the PKI library" OFF)


if (KRITIS3M_PKI_LIBRARY_ONLY)
    add_subdirectory(library)
else()
    # The CLI tools depend on the library and hence include it
    add_subdirectory(cli_tools)
endif()
