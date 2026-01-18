cmake_minimum_required(VERSION 3.30)

project(buffer-overflow LANGUAGES C)

if (${PROJECT_SOURCE_DIR} STREQUAL ${PROJECT_BINARY_DIR})
    message(FATAL_ERROR "In-source build is forbidden")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(NO_STACK_PROTECTOR "disable stack protector")

message(STATUS ${CMAKE_SYSTEM_NAME})
message(STATUS ${CMAKE_SYSTEM_PROCESSOR})

if (NOT DEFINED BUFFER_SIZE)
    message(FATAL_ERROR "Define BUFFER_SIZE variable to a positive integer")
endif()

add_executable(buffer_overflow
    src/main.c
    src/vulnerable.c
)
target_include_directories(buffer_overflow PRIVATE include)
target_compile_definitions(buffer_overflow PRIVATE BUFFER_SIZE=${BUFFER_SIZE})
