include(CMakeFindDependencyMacro)

get_filename_component(SELF_DIR "${CMAKE_CURRENT_LIST_FILE}" PATH)

find_dependency(Threads)
find_dependency(liboqs)
find_dependency(wolfssl)

include(${SELF_DIR}/../kritis3m_pki_common/kritis3m_pki_common-export.cmake)
include(${SELF_DIR}/kritis3m_pki_server-export.cmake)
