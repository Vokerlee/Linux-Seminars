#########################################################################

# CMAKE MINIMAL VERSION
cmake_minimum_required (VERSION 3.8)

# PROJECT PROPERTIES
project ("Socket seminar" LANGUAGES C)

#########################################################################

# ASSEMBLY OPTIONS

if(NOT CMAKE_C_EXTENSIONS)
    set(CMAKE_C_EXTENSIONS OFF)
endif()

add_compile_options(
    -Wall
    -Wpedantic

    -Wno-pointer-to-int-cast
    -Wno-int-to-pointer-cast
    -Wno-variadic-macros
    -Wno-unused-variable
    -Wno-unused-parameter
    -Wno-unused-function
    -Wno-sign-compare
    -Wno-misleading-indentation
)

#########################################################################

# UDT LIBRARY
 
set(UDT_PROTOCOL_LIB_NAME "udt_prot")

set(UDT_PROTOCOL_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/net/udt/src/udt_api.c
    ${CMAKE_CURRENT_SOURCE_DIR}/net/udt/src/udt_buffer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/net/udt/src/udt_buffer_ctl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/net/udt/src/udt_core.c
    ${CMAKE_CURRENT_SOURCE_DIR}/net/udt/src/udt_packet.c
)

add_library(${UDT_PROTOCOL_LIB_NAME} STATIC)
target_include_directories(${UDT_PROTOCOL_LIB_NAME} PRIVATE net/udt/src PRIVATE net/udt/include PRIVATE net)
target_sources(${UDT_PROTOCOL_LIB_NAME} PRIVATE ${UDT_PROTOCOL_SRC})

#########################################################################

# CLIENT & SERVER

set(SERVER_FILE_NAME "server")
set(CLIENT_FILE_NAME "client")

set(HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/net/net.h
)

set(SERVER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/server.c
    ${CMAKE_CURRENT_SOURCE_DIR}/server_tcp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/server_udp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/net/ipv4_net.c
    ${CMAKE_CURRENT_SOURCE_DIR}/utils/utils.c
)

set(CLIENT_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/client.c
    ${CMAKE_CURRENT_SOURCE_DIR}/client_tcp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/client_udp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/net/ipv4_net.c
    ${CMAKE_CURRENT_SOURCE_DIR}/utils/utils.c
)

# EXECUTABLE FILE
add_executable(${SERVER_FILE_NAME} ${SERVER_SOURCES})
add_executable(${CLIENT_FILE_NAME} ${CLIENT_SOURCES})

target_include_directories(${SERVER_FILE_NAME} PRIVATE net PRIVATE utils PRIVATE net/udt/include)
target_include_directories(${CLIENT_FILE_NAME} PRIVATE net PRIVATE utils PRIVATE net/udt/include)

target_link_libraries(${SERVER_FILE_NAME} ${UDT_PROTOCOL_LIB_NAME})
target_link_libraries(${CLIENT_FILE_NAME} ${UDT_PROTOCOL_LIB_NAME})

#########################################################################
