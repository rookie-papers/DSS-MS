cmake_minimum_required(VERSION 3.14)
project(DSS-MS)

# Force C++17 standard compliance
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Disable automatic updates to prevent accidental local Git conflicts
set(FETCHCONTENT_UPDATES_DISCONNECTED ON) 

# ============================================================================
# 1. External Dependencies via FetchContent
# ============================================================================
include(FetchContent)

FetchContent_Declare(
        WrapperLib
        GIT_REPOSITORY https://github.com/rookie-papers/miracl-wrapper.git
        GIT_TAG        main
)
# Download and populate the wrapper library
FetchContent_MakeAvailable(WrapperLib)

# ============================================================================
# 2. Project Subdirectories
# ============================================================================
add_subdirectory(external)
add_subdirectory(DSS-websocket)

# ============================================================================
# 3. Macro/Function to Register Cryptographic Schemes
# ============================================================================
function(add_scheme_executable name)
    set(SCHEME_DIR ${CMAKE_SOURCE_DIR}/${name})

    # A. Gather source files dedicated to this specific scheme
    file(GLOB SCHEME_SRC
            "${SCHEME_DIR}/src/*.cpp"
    )

    # B. Define the executable target
    add_executable(${name}_exec ${SCHEME_SRC})

    # C. Target-specific include directories
    # Note: WrapperLib headers are automatically propagated via linking
    target_include_directories(${name}_exec PRIVATE
            ${SCHEME_DIR}/include
    )

    # D. Link dependencies 
    # WrapperLib bundles MIRACL Core, GMP, and global system utilities
    target_link_libraries(${name}_exec PRIVATE
            WrapperLib
            benchmark::benchmark
    )
    
    message(STATUS "Configured scheme target: ${name}_exec")
endfunction()

# ============================================================================
# 4. Target Registration
# ============================================================================
add_scheme_executable(DSS)
add_scheme_executable(BFLS10)
add_scheme_executable(DVAS)
add_scheme_executable(IBSDIA)