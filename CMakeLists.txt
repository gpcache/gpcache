# At the time of writing this the supported/required versions are:
# Ubuntu 18.04: 3.10.2
# Ubuntu 20.04: 3.16.3
# Visual Studio: 3.14
# llvm minimum version: 3.13.4
# There is no special significance of those 3,
# it's just to get an idea about what others use.
cmake_minimum_required(VERSION 3.13.4)

project(gpcache
  DESCRIPTION "a general purpose cache"
  HOMEPAGE_URL "https://github.com/gpcache"
  LANGUAGES CXX
)

# At the time of writing this the required versions are:
# llvm: C++14
# Chromium: C++14 (C++17 mid 2021)
# However gpcache is a new project and there is no reason to start with an old
# language. Ok ok, there are lots of reasons, but I choose to ignore them.
# This roughly requires following compilers, although definetly not all C++20 
# features are supported in them. That's what CI is for.
# clang 10
# gcc 10
# MSVC 16.3
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS NO)

# Always export compile_commands.json since it's useful for some tools.
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(ENABLE_TESTING "Enable tests" ON)
if(ENABLE_TESTING)
  enable_testing()

  # Note: VERSION_GREATER_EQUAL requires CMake 3.17
  if(NOT ${CMAKE_VERSION} VERSION_LESS "3.17")
    list(APPEND CMAKE_CTEST_ARGUMENTS "--output-on-failure")
  endif()
endif()

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup(TARGETS)

add_executable(gpcache gpcache.cpp)
target_link_libraries(gpcache ${CONAN_TARGETS})
