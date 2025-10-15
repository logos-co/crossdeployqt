cmake_minimum_required(VERSION 3.16)

project(crossdeployqt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(crossdeployqt
  src/main.cpp
)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(crossdeployqt PRIVATE -Wall -Wextra -Wpedantic)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  target_compile_options(crossdeployqt PRIVATE /W4 /permissive-)
endif()

target_compile_definitions(crossdeployqt PRIVATE
  $<$<CONFIG:Debug>:DEBUG_BUILD>
)


