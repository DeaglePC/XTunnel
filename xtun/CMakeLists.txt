cmake_minimum_required(VERSION 2.8)
project(xtun)

# set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

set(CMAKE_CXX_COMPILER g++)

add_subdirectory(src)

set(SERVER_TARGET "xtuns")
set(CLIENT_TARGET "xtunc")

#aux_source_directory(${CMAKE_CURRENT_LIST_DIR}/src SRC)

include_directories(
        ${CMAKE_CURRENT_LIST_DIR}/src/net
        ${CMAKE_CURRENT_LIST_DIR}/src/msg
        ${CMAKE_CURRENT_LIST_DIR}/src/server
        ${CMAKE_CURRENT_LIST_DIR}/src/client
        ${CMAKE_CURRENT_LIST_DIR}/src/third_part
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/bin/)

add_executable(${SERVER_TARGET} ${CMAKE_CURRENT_LIST_DIR}/src/xtuns.cpp)
target_link_libraries(${SERVER_TARGET} server msg net third_part)

add_executable(${CLIENT_TARGET} ${CMAKE_CURRENT_LIST_DIR}/src/xtunc.cpp)
target_link_libraries(${CLIENT_TARGET} client msg net third_part)


set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
