
cmake_minimum_required(VERSION 3.18)
project(aliprop CXX)
set(CMAKE_CXX_STANDARD 17)
add_library(aliprop SHARED aliprop.cpp)
target_compile_options(aliprop PRIVATE -Os -fvisibility=hidden)
target_link_libraries(aliprop log)
