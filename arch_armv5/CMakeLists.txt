cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(arch_armv5)

# Find Binary Ninja API
if(NOT BN_INTERNAL_BUILD)
    # Look for the Binary Ninja API
    if(NOT DEFINED BN_API_PATH)
        # Try to find it in common locations
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../binaryninja-api")
            set(BN_API_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../binaryninja-api")
        elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../binaryninja-api")
            set(BN_API_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../binaryninja-api")
        else()
            message(FATAL_ERROR "Could not find Binary Ninja API. Please set BN_API_PATH.")
        endif()
    endif()

    add_subdirectory(${BN_API_PATH} ${PROJECT_BINARY_DIR}/api)
endif()

# Gather source files
file(GLOB SOURCES CONFIGURE_DEPENDS
    *.cpp
    *.h
    armv5_disasm/armv5.c
    armv5_disasm/armv5.h
    thumb_disasm/*.cpp
    thumb_disasm/*.c
    thumb_disasm/*.h)

# Build as shared library (plugin)
if(DEMO)
    add_library(arch_armv5 STATIC ${SOURCES})
else()
    add_library(arch_armv5 SHARED ${SOURCES})
endif()

# Include directories
target_include_directories(arch_armv5
    PRIVATE ${PROJECT_SOURCE_DIR}
    PRIVATE ${PROJECT_SOURCE_DIR}/armv5_disasm
    PRIVATE ${PROJECT_SOURCE_DIR}/thumb_disasm)

# Link against Binary Ninja API
target_link_libraries(arch_armv5 binaryninjaapi)

# Compiler settings
set_target_properties(arch_armv5 PROPERTIES
    CXX_STANDARD 20
    CXX_VISIBILITY_PRESET hidden
    CXX_STANDARD_REQUIRED ON
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON)

# Platform-specific settings
if(APPLE)
    set_target_properties(arch_armv5 PROPERTIES
        SUFFIX ".dylib")
elseif(WIN32)
    set_target_properties(arch_armv5 PROPERTIES
        SUFFIX ".dll")
else()
    set_target_properties(arch_armv5 PROPERTIES
        SUFFIX ".so")
endif()

# Installation
if(BN_INTERNAL_BUILD)
    plugin_rpath(arch_armv5)
    set_target_properties(arch_armv5 PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
        RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
else()
    # Install to user plugins directory
    if(APPLE)
        set(BN_USER_PLUGINS "$ENV{HOME}/.binaryninja-dev/plugins")
    elseif(WIN32)
        set(BN_USER_PLUGINS "$ENV{APPDATA}/Binary Ninja/plugins")
    else()
        set(BN_USER_PLUGINS "$ENV{HOME}/.binaryninja/plugins")
    endif()

    install(TARGETS arch_armv5
        LIBRARY DESTINATION "${BN_USER_PLUGINS}"
        RUNTIME DESTINATION "${BN_USER_PLUGINS}")
endif()

# Print build info
message(STATUS "Building ARMv5 architecture plugin")
message(STATUS "  Output: ${CMAKE_CURRENT_BINARY_DIR}")
