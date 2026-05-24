# ============================================================================
# CMake Configuration for DSS-MS WebSocket Simulation
# ============================================================================

# 1. Find Boost libraries required by WebSocketpp
find_package(Boost REQUIRED COMPONENTS system thread)

# 2. Gather WebSocket simulation source files
file(GLOB SIMULATION_SRC_FILES "src/*.cpp")

# 3. Gather common sources (e.g., Serializer.cpp)
file(GLOB COMMON_SRC "${CMAKE_SOURCE_DIR}/common/src/*.cpp")

# 4. Specify the core DSS scheme source (or alternative base file if applicable)
set(DSS_SCHEME_SRC "${CMAKE_CURRENT_SOURCE_DIR}/scheme/DSS-websocket.cpp")

# ============================================================================
# Executable Generation
# ============================================================================
foreach(file ${SIMULATION_SRC_FILES})
    # Extract the base filename (e.g., "src/Sanitizer.cpp" -> "Sanitizer")
    get_filename_component(filename ${file} NAME_WE)

    # 1. Create a UNIQUE target name
    set(target_name "${filename}_exec")

    # 2. Define the executable using the correct source paths
    add_executable(${target_name}
            ${file}
            ${COMMON_SRC}       # Includes local common files (Serializer, etc.)
            ${DSS_SCHEME_SRC}   # Includes core scheme logic
    )

    # 3. Specify include directories
    target_include_directories(${target_name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/common/include   # For local headers like Serializer.h
            ${CMAKE_SOURCE_DIR}/DSS/include      # For core DSS scheme headers
    )

    # 4. Link required libraries (Replacing legacy miracl/gmp targets with WrapperLib)
    target_link_libraries(${target_name}
            PRIVATE
            WrapperLib          # Automatically provides MIRACL, GMP, and Tools.h
            websocketpp
            ${Boost_LIBRARIES} 
            pthread
    )
endforeach()