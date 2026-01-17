# ARMv5 UI Plugin
#
# This is a separate UI plugin that provides a sidebar widget for ARMv5 analysis.
# It links against binaryninjaui and Qt6, which are only available when Binary Ninja
# runs with its UI.
#
# Building this plugin:
#   1. Set BN_INSTALL_DIR to your Binary Ninja installation
#   2. cmake -B build -S . -DBN_INSTALL_DIR=/path/to/binaryninja
#   3. cmake --build build
#
# The plugin will be placed in .build/ alongside the core plugin.

cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(arch_armv5_ui)

# Enable Qt MOC (Meta Object Compiler) for signal/slot support
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

# Binary Ninja paths
if(NOT DEFINED BN_INSTALL_DIR)
    if(APPLE)
        set(BN_INSTALL_DIR "/Applications/Binary Ninja DEV.app" CACHE PATH "Binary Ninja installation")
    elseif(WIN32)
        set(BN_INSTALL_DIR "C:/Program Files/Vector35/BinaryNinja" CACHE PATH "Binary Ninja installation")
    else()
        set(BN_INSTALL_DIR "$ENV{HOME}/binaryninja" CACHE PATH "Binary Ninja installation")
    endif()
endif()

if(NOT DEFINED BN_API_PATH)
    set(BN_API_PATH "${CMAKE_SOURCE_DIR}/../binaryninja-api" CACHE PATH "Binary Ninja API path")
endif()

# Build the arch_armv5 core library (which also builds binaryninjaapi)
add_subdirectory(${CMAKE_SOURCE_DIR}/../arch_armv5 ${PROJECT_BINARY_DIR}/arch_armv5)

# Find Qt6
find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

# Find Binary Ninja UI library
if(APPLE)
    set(BN_UI_LIB "${BN_INSTALL_DIR}/Contents/MacOS/libbinaryninjaui.dylib")
    set(BN_CORE_LIB "${BN_INSTALL_DIR}/Contents/MacOS/libbinaryninjacore.dylib")
elseif(WIN32)
    set(BN_UI_LIB "${BN_INSTALL_DIR}/binaryninjaui.lib")
    set(BN_CORE_LIB "${BN_INSTALL_DIR}/binaryninjacore.lib")
else()
    set(BN_UI_LIB "${BN_INSTALL_DIR}/libbinaryninjaui.so")
    set(BN_CORE_LIB "${BN_INSTALL_DIR}/libbinaryninjacore.so")
endif()

if(NOT EXISTS "${BN_UI_LIB}")
    message(FATAL_ERROR "Binary Ninja UI library not found at ${BN_UI_LIB}")
endif()

# Collect source files
file(GLOB UI_SOURCES CONFIGURE_DEPENDS
    *.cpp *.h
    sidebar/*.cpp sidebar/*.h
    widgets/*.cpp widgets/*.h
    widgets/common/*.cpp widgets/common/*.h
    widgets/discover/*.cpp widgets/discover/*.h
    widgets/security/*.cpp widgets/security/*.h
    widgets/health/*.cpp widgets/health/*.h
    widgets/diff/*.cpp widgets/diff/*.h)

# Filter out MOC-generated files
list(FILTER UI_SOURCES EXCLUDE REGEX "moc_.*")
list(FILTER UI_SOURCES EXCLUDE REGEX "qrc_.*")

add_library(arch_armv5_ui SHARED ${UI_SOURCES})

# Include directories
target_include_directories(arch_armv5_ui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../arch_armv5
    ${BN_API_PATH}
    ${BN_API_PATH}/ui)

# Link libraries
target_link_libraries(arch_armv5_ui
    arch_armv5
    binaryninjaapi
    ${BN_UI_LIB}
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets)

# C++20 standard
set_target_properties(arch_armv5_ui PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON)

# Output directory
set_target_properties(arch_armv5_ui PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../.build
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../.build)

# Platform-specific suffix
if(APPLE)
    set_target_properties(arch_armv5_ui PROPERTIES SUFFIX ".dylib")
    
    # Set RPATH to find Binary Ninja libraries
    set_target_properties(arch_armv5_ui PROPERTIES
        BUILD_RPATH "${BN_INSTALL_DIR}/Contents/MacOS;${BN_INSTALL_DIR}/Contents/Frameworks"
        INSTALL_RPATH "${BN_INSTALL_DIR}/Contents/MacOS;${BN_INSTALL_DIR}/Contents/Frameworks")
elseif(WIN32)
    set_target_properties(arch_armv5_ui PROPERTIES SUFFIX ".dll")
else()
    set_target_properties(arch_armv5_ui PROPERTIES SUFFIX ".so")
    
    set_target_properties(arch_armv5_ui PROPERTIES
        BUILD_RPATH "${BN_INSTALL_DIR}"
        INSTALL_RPATH "${BN_INSTALL_DIR}")
endif()

message(STATUS "")
message(STATUS "ARMv5 UI Plugin Configuration")
message(STATUS "  Binary Ninja: ${BN_INSTALL_DIR}")
message(STATUS "  UI Library: ${BN_UI_LIB}")
message(STATUS "  Qt6: ${Qt6_DIR}")
message(STATUS "")
