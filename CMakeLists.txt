cmake_minimum_required(VERSION 3.16)

project(crossdeployqt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(crossdeployqt
  src/main.cpp
  src/cdqt/args.cpp
  src/cdqt/binary_detect.cpp
  src/cdqt/common.cpp
  src/cdqt/util.cpp
  src/cdqt/tools.cpp
  src/cdqt/qt_paths.cpp
  src/cdqt/deps_parse.cpp
  src/cdqt/resolve.cpp
  src/cdqt/fs_ops.cpp
  src/cdqt/pe_patch.cpp
  src/cdqt/stage.cpp
  src/cdqt/qml.cpp
  src/cdqt/translations.cpp
  src/cdqt/macho_fixups.cpp
  src/cdqt/deploy.cpp
)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(crossdeployqt PRIVATE -Wall -Wextra -Wpedantic)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  target_compile_options(crossdeployqt PRIVATE /W4 /permissive-)
endif()

target_compile_definitions(crossdeployqt PRIVATE
  $<$<CONFIG:Debug>:DEBUG_BUILD>
)


