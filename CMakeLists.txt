cmake_minimum_required(VERSION 3.17)
project(infinitas_acpfix)

set(CMAKE_CXX_STANDARD 20)

add_subdirectory(subprojects/MinHook EXCLUDE_FROM_ALL)

add_definitions(-DWIN32_LEAN_AND_MEAN)
add_library(${PROJECT_NAME} SHARED src/library.cpp)

target_link_libraries(${PROJECT_NAME} minhook)