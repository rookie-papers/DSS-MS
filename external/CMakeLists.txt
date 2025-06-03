# external/CMakeLists.txt
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/gmp-install/include)

# ------------------------  compile miracl, select BLS12381 curve  ----------------------------------
set(MIRACL_CORE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/miracl_core)
set(MIRACL_CPP_DIR ${MIRACL_CORE_DIR}/cpp)
set(MIRACL_CONFIG_PY ${MIRACL_CPP_DIR}/config64.py)
set(MIRACL_CONFIG_DONE_FILE ${MIRACL_CPP_DIR}/.miracl_configured_bls12381)
set(MIRACL_STATIC_LIB ${MIRACL_CPP_DIR}/core.a)

# Make sure you have the python3 compiler
find_package(Python3 REQUIRED COMPONENTS Interpreter)

# run config64.py (input 31 0), gain core.a
add_custom_command(
        OUTPUT ${MIRACL_CONFIG_DONE_FILE}
        COMMAND ${CMAKE_COMMAND} -E echo "Configuring MIRACL Core with BLS12381"
        COMMAND ${CMAKE_COMMAND} -E env bash ${CMAKE_CURRENT_SOURCE_DIR}/run_miracl_config.sh
        COMMAND ${CMAKE_COMMAND} -E touch ${MIRACL_CONFIG_DONE_FILE}
        DEPENDS ${MIRACL_CONFIG_PY}
        COMMENT "Running MIRACL Core config script"
)

# Virtual target: indicates that the configuration is complete
add_custom_target(miracl_core_configure
        DEPENDS ${MIRACL_CONFIG_DONE_FILE}
)

# Use the generated core.a file and import it as a static library target
add_library(miracl_core STATIC IMPORTED GLOBAL)
add_dependencies(miracl_core miracl_core_configure)

set_target_properties(miracl_core PROPERTIES
        IMPORTED_LOCATION ${MIRACL_STATIC_LIB}
        INTERFACE_INCLUDE_DIRECTORIES ${MIRACL_CPP_DIR}
)


# ------------------------  compile benchmark lib  ----------------------------------
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Disable benchmark tests" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "Disable install" FORCE)
add_subdirectory(benchmark)

# ------------------------  compile gmp lib  ----------------------------------
add_subdirectory(gmp)

# ------------------------  header-only websocketpp lib  ----------------------------------
add_library(websocketpp INTERFACE)
target_include_directories(websocketpp INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/websocketpp)