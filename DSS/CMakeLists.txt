add_library(dss_core STATIC src/DSS.cpp)
target_include_directories(dss_core PUBLIC include)
target_link_libraries(dss_core PUBLIC WrapperLib)

add_executable(DSS_exec
    bench/benchmark.cpp
    bench/baselines.cpp
    ${PROJECT_SOURCE_DIR}/ECMSS/src/ECMSS.cpp
    ${PROJECT_SOURCE_DIR}/ECMSS/src/benchmark.cpp
    ${PROJECT_SOURCE_DIR}/LSanS/src/LSanS.cpp
    ${PROJECT_SOURCE_DIR}/LSanS/src/benchmark.cpp
    ${PROJECT_SOURCE_DIR}/PGUS_SBS/src/PGUS_SBS.cpp
    ${PROJECT_SOURCE_DIR}/PGUS_SBS/src/Primitives.cpp
    ${PROJECT_SOURCE_DIR}/PGUS_SBS/src/SPSEQ.cpp
    ${PROJECT_SOURCE_DIR}/PGUS_SBS/src/TRS.cpp
    ${PROJECT_SOURCE_DIR}/PGUS_SBS/src/PKE.cpp
    ${PROJECT_SOURCE_DIR}/PGUS_SBS/src/benchmark.cpp
    ${PROJECT_SOURCE_DIR}/IUT_k_SAN/src/iut_k_san.cpp
    ${PROJECT_SOURCE_DIR}/IUT_k_SAN/src/eqs.cpp
    ${PROJECT_SOURCE_DIR}/IUT_k_SAN/src/pke.cpp
    ${PROJECT_SOURCE_DIR}/IUT_k_SAN/src/vrs.cpp
    ${PROJECT_SOURCE_DIR}/PF_CLSS_DV/src/PF_CLSS_DV.cpp
)
target_include_directories(DSS_exec PRIVATE
    bench
    ${PROJECT_SOURCE_DIR}/common/include
    ${PROJECT_SOURCE_DIR}/ECMSS/include
    ${PROJECT_SOURCE_DIR}/LSanS/include
    ${PROJECT_SOURCE_DIR}/PGUS_SBS/include
    ${PROJECT_SOURCE_DIR}/IUT_k_SAN/include
    ${PROJECT_SOURCE_DIR}/PF_CLSS_DV/include
)
target_link_libraries(DSS_exec PRIVATE dss_core benchmark::benchmark)
set_target_properties(DSS_exec PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
target_compile_definitions(DSS_exec PRIVATE DSS_COMPILER="${CMAKE_CXX_COMPILER_ID}-${CMAKE_CXX_COMPILER_VERSION}" DSS_BUILD_TYPE="$<CONFIG>")
foreach(script IN ITEMS plot_results.py collect_energy.py)
    configure_file(bench/${script} ${CMAKE_BINARY_DIR}/${script} COPYONLY)
endforeach()

execute_process(COMMAND git describe --always --dirty
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    OUTPUT_VARIABLE DSS_REVISION OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
execute_process(COMMAND git rev-parse HEAD
    WORKING_DIRECTORY ${wrapperlib_SOURCE_DIR}
    OUTPUT_VARIABLE DSS_WRAPPER_REVISION OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
target_compile_definitions(DSS_exec PRIVATE
    DSS_GIT_REVISION="${DSS_REVISION}" DSS_WRAPPER_REVISION="${DSS_WRAPPER_REVISION}")
