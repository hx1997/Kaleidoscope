cmake_minimum_required(VERSION 3.8)
project(Kaleidoscope)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES main.c config.c config.h disassemble.c instruction.h disassemble.h instruction.c peparser.c peparser.h search.c search.h)
add_executable(klp ${SOURCE_FILES})