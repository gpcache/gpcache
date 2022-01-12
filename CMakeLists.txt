# At the time of writing this the supported/required versions are:
# Ubuntu 18.04: 3.10.2
# Ubuntu 20.04: 3.16.3
# Visual Studio: 3.19 (since 16.9.0 in March 2021)
# llvm minimum version: 3.13.4
# There is no special significance of this list,
# it's just to get an idea about what others use.
cmake_minimum_required(VERSION 3.16.3)

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

if((CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 10)
   OR (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 10)
   OR (CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang"))
  message(FATAL_ERROR
          "The compiler you are using "
          "(${CMAKE_CXX_COMPILER_ID}, ${CMAKE_CXX_COMPILER_VERSION}) is too old, "
          "it does not support all required features. Please use at least "
          "gcc 10 or clang 10.")
endif()


# Always export compile_commands.json since it's useful for some tools.
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

# ToDo
option(ASAN "Enable ASAN" TRUE)
if(ASAN)
  add_compile_options(
    -fsanitize=address
    -fsanitize=leak
    -fsanitize=bounds
    -fsanitize=bool
    -fsanitize=enum
    -fsanitize=vptr
    -fsanitize=float-divide-by-zero
    -fsanitize=undefined
    -fno-sanitize-recover=all
  )
  add_link_options(
    -fsanitize=address
    -fsanitize=leak
    -fsanitize=bounds
    -fsanitize=bool
    -fsanitize=enum
    -fsanitize=vptr
    -fsanitize=float-divide-by-zero
    -fsanitize=undefined
    -fno-sanitize-recover=all
  )
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(ENABLE_TESTING "Enable tests" ON)
if(ENABLE_TESTING)
  enable_testing()
  list(APPEND CMAKE_CTEST_ARGUMENTS "--output-on-failure")
endif()

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup(TARGETS)


option (FORCE_COLORED_OUTPUT "Always produce ANSI-colored output (GNU/Clang only)." FALSE)
if (${FORCE_COLORED_OUTPUT})
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
       add_compile_options (-fdiagnostics-color=always)
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
      add_compile_options (-fcolor-diagnostics)
    endif ()
endif ()

if (MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -pedantic)
endif()


add_library(gpcache_lib
  utils/flag_to_string.cpp
  utils/stacktrace.cpp

  wrappers/hash.cpp
  wrappers/posix.cpp
  wrappers/ptrace.cpp
  wrappers/ptrace_linux_x64/SyscallMap.cpp

  backend/file.cpp

  main/cache_executed_syscall.cpp
  main/execute_cached_syscall.cpp
  main/state.cpp

  syscalls/access.cpp
  syscalls/close.cpp
  syscalls/fstat.cpp
  syscalls/mmap_munmap.cpp
  syscalls/open.cpp
  syscalls/read.cpp
  syscalls/write.cpp
)
set_source_files_properties(execution.cpp PROPERTIES COMPILE_FLAGS -Wno-missing-field-initializers)

target_include_directories(gpcache_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(gpcache_lib ${CONAN_TARGETS} ${CMAKE_DL_LIBS})

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  add_compile_definitions(gpcache_lib USE_ELFUTILS)
endif()

# GNU implementation prior to 9.1 requires linking with -lstdc++fs and LLVM implementation prior to LLVM 9.0 requires linking with -lc++fs.
find_library(FS_LIB stdc++fs)
if(NOT FS_LIB)
  find_library(FS_LIB c++fs)
endif()
if(FS_LIB)
  #target_link_libraries(gpcache_lib ${FS_LIB})
endif()

add_executable(gpcache main.cpp)
target_link_libraries(gpcache gpcache_lib)

add_executable(test1 tests/test1.cpp)
target_link_libraries(test1 gpcache_lib)

add_executable(test2 tests/test2.cpp)
target_link_libraries(test2 gpcache_lib)
