cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(armv5_binaryninja)

# Set output directory to .build at project root
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/.build)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/.build)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/.build)

# Also set for multi-config generators (like Xcode)
foreach(OUTPUTCONFIG ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${CMAKE_SOURCE_DIR}/.build)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${CMAKE_SOURCE_DIR}/.build)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${CMAKE_SOURCE_DIR}/.build)
endforeach()

# Binary Ninja installation directory (for finding headers/libs)
# Default to DEV version on macOS since that's what we use for development
if(APPLE)
    set(BN_INSTALL_DIR "/Applications/Binary Ninja DEV.app" CACHE PATH "Binary Ninja installation directory")
elseif(WIN32)
    set(BN_INSTALL_DIR "C:/Program Files/Vector35/BinaryNinja" CACHE PATH "Binary Ninja installation directory")
else()
    set(BN_INSTALL_DIR "$ENV{HOME}/binaryninja" CACHE PATH "Binary Ninja installation directory")
endif()

# Binary Ninja API path
if(NOT DEFINED BN_API_PATH)
    set(BN_API_PATH "${CMAKE_SOURCE_DIR}/binaryninja-api" CACHE PATH "Binary Ninja API path")
endif()

if(NOT EXISTS "${BN_API_PATH}/CMakeLists.txt")
    message(FATAL_ERROR "Binary Ninja API not found at ${BN_API_PATH}. Run: git submodule update --init --recursive")
endif()

# Add Binary Ninja API
add_subdirectory(${BN_API_PATH} ${CMAKE_BINARY_DIR}/api)

# ============================================================================
# ARMv5 Architecture Plugin
# ============================================================================

set(ARCH_ARMV5_DIR ${CMAKE_SOURCE_DIR}/arch_armv5)

file(GLOB ARCH_ARMV5_SOURCES CONFIGURE_DEPENDS
    ${ARCH_ARMV5_DIR}/*.cpp
    ${ARCH_ARMV5_DIR}/*.h
    ${ARCH_ARMV5_DIR}/arch/*.cpp
    ${ARCH_ARMV5_DIR}/arch/*.h
    ${ARCH_ARMV5_DIR}/analysis/*.cpp
    ${ARCH_ARMV5_DIR}/analysis/*.h
    ${ARCH_ARMV5_DIR}/commands/*.cpp
    ${ARCH_ARMV5_DIR}/commands/*.h
    ${ARCH_ARMV5_DIR}/common/*.h
    ${ARCH_ARMV5_DIR}/conventions/*.cpp
    ${ARCH_ARMV5_DIR}/conventions/*.h
    ${ARCH_ARMV5_DIR}/recognizers/*.cpp
    ${ARCH_ARMV5_DIR}/recognizers/*.h
    ${ARCH_ARMV5_DIR}/platforms/*.cpp
    ${ARCH_ARMV5_DIR}/platforms/*.h
    ${ARCH_ARMV5_DIR}/firmware/*.cpp
    ${ARCH_ARMV5_DIR}/firmware/*.h
    ${ARCH_ARMV5_DIR}/settings/*.cpp
    ${ARCH_ARMV5_DIR}/settings/*.h
    ${ARCH_ARMV5_DIR}/workflow/*.cpp
    ${ARCH_ARMV5_DIR}/workflow/*.h
    ${ARCH_ARMV5_DIR}/il/*.cpp
    ${ARCH_ARMV5_DIR}/il/*.h
    ${ARCH_ARMV5_DIR}/relocations/*.cpp
    ${ARCH_ARMV5_DIR}/relocations/*.h
    ${ARCH_ARMV5_DIR}/armv5_disasm/armv5.c
    ${ARCH_ARMV5_DIR}/armv5_disasm/armv5.h
    ${ARCH_ARMV5_DIR}/thumb_disasm/*.cpp
    ${ARCH_ARMV5_DIR}/thumb_disasm/*.c
    ${ARCH_ARMV5_DIR}/thumb_disasm/*.h)

add_library(arch_armv5 SHARED ${ARCH_ARMV5_SOURCES})

target_include_directories(arch_armv5 PRIVATE
    ${ARCH_ARMV5_DIR}
    ${ARCH_ARMV5_DIR}/analysis
    ${ARCH_ARMV5_DIR}/common
    ${ARCH_ARMV5_DIR}/armv5_disasm
    ${ARCH_ARMV5_DIR}/thumb_disasm)

target_link_libraries(arch_armv5 binaryninjaapi)

set_target_properties(arch_armv5 PROPERTIES
    CXX_STANDARD 20
    CXX_VISIBILITY_PRESET hidden
    CXX_STANDARD_REQUIRED ON
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON)

# Platform-specific suffix
if(APPLE)
    set_target_properties(arch_armv5 PROPERTIES SUFFIX ".dylib")
elseif(WIN32)
    set_target_properties(arch_armv5 PROPERTIES SUFFIX ".dll")
else()
    set_target_properties(arch_armv5 PROPERTIES SUFFIX ".so")
endif()

# ============================================================================
# Standalone Disassembler Test Tool
# ============================================================================

add_executable(armv5_disasm_test
    ${ARCH_ARMV5_DIR}/armv5_disasm/test.c
    ${ARCH_ARMV5_DIR}/armv5_disasm/armv5.c)

target_include_directories(armv5_disasm_test PRIVATE
    ${ARCH_ARMV5_DIR}/armv5_disasm)

set_target_properties(armv5_disasm_test PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    OUTPUT_NAME "test_armv5")

# ============================================================================
# Disassembler Shared Library (for Python ctypes tests)
# ============================================================================

add_library(armv5_disasm_lib SHARED
    ${ARCH_ARMV5_DIR}/armv5_disasm/armv5.c)

target_include_directories(armv5_disasm_lib PRIVATE
    ${ARCH_ARMV5_DIR}/armv5_disasm)

set_target_properties(armv5_disasm_lib PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    OUTPUT_NAME "disasm")

if(APPLE)
    set_target_properties(armv5_disasm_lib PROPERTIES SUFFIX ".dylib")
elseif(WIN32)
    set_target_properties(armv5_disasm_lib PROPERTIES SUFFIX ".dll")
else()
    set_target_properties(armv5_disasm_lib PROPERTIES SUFFIX ".so")
endif()

# ============================================================================
# ARMv5 UI Plugin (optional, requires Qt6)
# ============================================================================

option(BUILD_UI_PLUGIN "Build the ARMv5 UI plugin (requires Qt6)" OFF)

if(BUILD_UI_PLUGIN)
    # Enable Qt MOC
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTOUIC ON)
    set(CMAKE_AUTORCC ON)
    
    find_package(Qt6 COMPONENTS Core Gui Widgets QUIET)
    
    if(Qt6_FOUND)
        # Find Binary Ninja UI library
        if(APPLE)
            set(BN_UI_LIB "${BN_INSTALL_DIR}/Contents/MacOS/libbinaryninjaui.dylib")
        elseif(WIN32)
            set(BN_UI_LIB "${BN_INSTALL_DIR}/binaryninjaui.lib")
        else()
            set(BN_UI_LIB "${BN_INSTALL_DIR}/libbinaryninjaui.so")
        endif()
        
        if(EXISTS "${BN_UI_LIB}")
            set(ARCH_ARMV5_UI_DIR ${CMAKE_SOURCE_DIR}/arch_armv5_ui)
            
            file(GLOB UI_SOURCES CONFIGURE_DEPENDS
                ${ARCH_ARMV5_UI_DIR}/*.cpp ${ARCH_ARMV5_UI_DIR}/*.h
                ${ARCH_ARMV5_UI_DIR}/sidebar/*.cpp ${ARCH_ARMV5_UI_DIR}/sidebar/*.h
                ${ARCH_ARMV5_UI_DIR}/widgets/*.cpp ${ARCH_ARMV5_UI_DIR}/widgets/*.h)
            
            # Filter out MOC-generated files
            list(FILTER UI_SOURCES EXCLUDE REGEX "moc_.*")
            list(FILTER UI_SOURCES EXCLUDE REGEX "qrc_.*")
            
            add_library(arch_armv5_ui SHARED ${UI_SOURCES})
            
            target_include_directories(arch_armv5_ui PRIVATE
                ${ARCH_ARMV5_UI_DIR}
                ${ARCH_ARMV5_DIR}
                ${BN_API_PATH}
                ${BN_API_PATH}/ui)
            
            target_link_libraries(arch_armv5_ui
                binaryninjaapi
                ${BN_UI_LIB}
                Qt6::Core
                Qt6::Gui
                Qt6::Widgets)
            
            set_target_properties(arch_armv5_ui PROPERTIES
                CXX_STANDARD 20
                CXX_STANDARD_REQUIRED ON
                CXX_VISIBILITY_PRESET hidden
                VISIBILITY_INLINES_HIDDEN ON
                POSITION_INDEPENDENT_CODE ON)
            
            if(APPLE)
                set_target_properties(arch_armv5_ui PROPERTIES SUFFIX ".dylib")
                set_target_properties(arch_armv5_ui PROPERTIES
                    BUILD_RPATH "${BN_INSTALL_DIR}/Contents/MacOS"
                    INSTALL_RPATH "${BN_INSTALL_DIR}/Contents/MacOS")
            elseif(WIN32)
                set_target_properties(arch_armv5_ui PROPERTIES SUFFIX ".dll")
            else()
                set_target_properties(arch_armv5_ui PROPERTIES SUFFIX ".so")
            endif()
            
            message(STATUS "UI Plugin: ENABLED (Qt6 ${Qt6_VERSION})")
        else()
            message(STATUS "UI Plugin: DISABLED (Binary Ninja UI library not found)")
        endif()
    else()
        message(STATUS "UI Plugin: DISABLED (Qt6 not found)")
    endif()
else()
    message(STATUS "UI Plugin: DISABLED (use -DBUILD_UI_PLUGIN=ON to enable)")
endif()

# ============================================================================
# Installation (creates symlink to plugin)
# ============================================================================

# User plugins directory
if(APPLE)
    set(BN_USER_PLUGINS "$ENV{HOME}/.binaryninja-dev/plugins" CACHE PATH "Binary Ninja plugins directory")
elseif(WIN32)
    set(BN_USER_PLUGINS "$ENV{APPDATA}/Binary Ninja/plugins" CACHE PATH "Binary Ninja plugins directory")
else()
    set(BN_USER_PLUGINS "$ENV{HOME}/.binaryninja/plugins" CACHE PATH "Binary Ninja plugins directory")
endif()

# Get the library filename with platform-specific suffix
if(APPLE)
    set(PLUGIN_FILENAME "libarch_armv5.dylib")
elseif(WIN32)
    set(PLUGIN_FILENAME "arch_armv5.dll")
else()
    set(PLUGIN_FILENAME "libarch_armv5.so")
endif()

# Build install target command list
set(INSTALL_PLUGIN_COMMANDS
    COMMAND ${CMAKE_COMMAND} -E make_directory "${BN_USER_PLUGINS}"
    COMMAND ${CMAKE_COMMAND} -E remove -f "${BN_USER_PLUGINS}/${PLUGIN_FILENAME}"
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        "${CMAKE_SOURCE_DIR}/.build/${PLUGIN_FILENAME}"
        "${BN_USER_PLUGINS}/${PLUGIN_FILENAME}"
)

set(INSTALL_PLUGIN_DEPS arch_armv5)

# Also install UI plugin if it was built
# Note: We check BUILD_UI_PLUGIN directly since the target was defined earlier in this file
if(BUILD_UI_PLUGIN)
    if(APPLE)
        set(UI_PLUGIN_FILENAME "libarch_armv5_ui.dylib")
    elseif(WIN32)
        set(UI_PLUGIN_FILENAME "arch_armv5_ui.dll")
    else()
        set(UI_PLUGIN_FILENAME "libarch_armv5_ui.so")
    endif()
    
    list(APPEND INSTALL_PLUGIN_COMMANDS
        COMMAND ${CMAKE_COMMAND} -E remove -f "${BN_USER_PLUGINS}/${UI_PLUGIN_FILENAME}"
        COMMAND ${CMAKE_COMMAND} -E create_symlink
            "${CMAKE_SOURCE_DIR}/.build/${UI_PLUGIN_FILENAME}"
            "${BN_USER_PLUGINS}/${UI_PLUGIN_FILENAME}"
    )
    list(APPEND INSTALL_PLUGIN_DEPS arch_armv5_ui)
endif()

# Custom install target that creates a symlink instead of copying
add_custom_target(install_plugin
    ${INSTALL_PLUGIN_COMMANDS}
    DEPENDS ${INSTALL_PLUGIN_DEPS}
    COMMENT "Creating symlink: ${BN_USER_PLUGINS}/${PLUGIN_FILENAME} -> ${CMAKE_SOURCE_DIR}/.build/${PLUGIN_FILENAME}"
)

# Also keep the standard install for package creation if needed
install(TARGETS arch_armv5
    LIBRARY DESTINATION "${BN_USER_PLUGINS}"
    RUNTIME DESTINATION "${BN_USER_PLUGINS}")

# ============================================================================
# Build Summary
# ============================================================================

message(STATUS "")
message(STATUS "ARMv5 Binary Ninja Plugin Build Configuration")
message(STATUS "  Binary Ninja: ${BN_INSTALL_DIR}")
message(STATUS "  API Path: ${BN_API_PATH}")
message(STATUS "  Output: ${CMAKE_SOURCE_DIR}/.build")
message(STATUS "  Install: ${BN_USER_PLUGINS}")
message(STATUS "")
message(STATUS "Targets:")
message(STATUS "  arch_armv5        - Binary Ninja architecture plugin")
if(TARGET arch_armv5_ui)
message(STATUS "  arch_armv5_ui     - Binary Ninja UI plugin")
endif()
message(STATUS "  armv5_disasm_test - Standalone disassembler test tool")
message(STATUS "  armv5_disasm_lib  - Shared library for Python tests")
message(STATUS "  install_plugin    - Create symlink in plugins directory")
message(STATUS "")
