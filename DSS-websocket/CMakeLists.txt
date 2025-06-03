file(GLOB SCHEME_SRC_FILES src/*.cpp)

file(GLOB COMMON_SRC
        ${CMAKE_SOURCE_DIR}/common/src/*.cpp
)

foreach(file ${SCHEME_SRC_FILES})
    get_filename_component(filename ${file} NAME_WE)

    add_executable(${filename}_exec ${file} ${COMMON_SRC} scheme/DSS-websocket.cpp)

    target_include_directories(${filename}_exec PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/common/include
    )

    target_link_libraries(${filename}_exec
            PRIVATE
            miracl_core
            gmp::gmp
            gmp::gmpxx
            benchmark::benchmark
            websocketpp
            ${Boost_LIBRARIES} pthread
    )
endforeach()