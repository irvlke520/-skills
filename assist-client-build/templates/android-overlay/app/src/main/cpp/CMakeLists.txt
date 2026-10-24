cmake_minimum_required(VERSION 3.22.1)

project(kernel_bridge C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(kernel_bridge SHARED kernel_bridge.c)

find_library(log-lib log)

target_link_libraries(kernel_bridge ${log-lib})
