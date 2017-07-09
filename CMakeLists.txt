cmake_minimum_required (VERSION 3.0)
project (dltrace)

add_compile_options(-std=c++14)

include_directories(ext/libelfin)
add_executable(dltrace dltrace.cpp)

add_custom_target(
   libelfin
   COMMAND make
   WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/ext/libelfin
   )
target_link_libraries(dltrace
                      ${PROJECT_SOURCE_DIR}/ext/libelfin/elf/libelf++.so)
add_dependencies(dltrace libelfin)
