cmake_minimum_required(VERSION 3.22)

project(kritis3m_pki)

option(KRITIS3M_PKI_LIBRARY_ONLY "Build only the PKI library" OFF)

if (KRITIS3M_PKI_LIBRARY_ONLY)
    add_subdirectory(library)
else()
    add_subdirectory(cli_tools)
endif()
