#########################################################################

# CMAKE MINIMAL VERSION
cmake_minimum_required (VERSION 3.8)

# PROJECT PROPERTIES
project ("vssh" LANGUAGES C)

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

# IPV4NET LIBRARY

set(IPV4NET_LIB_NAME "ipv4net")

set(IPV4NET_LIB_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/ipv4_net/udt/src/udt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ipv4_net/udt/src/udt_buffer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ipv4_net/udt/src/udt_buffer_ctl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ipv4_net/udt/src/udt_core.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ipv4_net/udt/src/udt_packet.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ipv4_net/ipv4_net.c
)

add_library(${IPV4NET_LIB_NAME} STATIC)
target_include_directories(${IPV4NET_LIB_NAME} PRIVATE ipv4_net/udt/src PRIVATE ipv4_net/udt/include PRIVATE ipv4_net utils)
target_sources(${IPV4NET_LIB_NAME} PRIVATE ${IPV4NET_LIB_SRC})

#########################################################################

# CLIENT & SERVER

set(SSH_SERVER_FILE_NAME "vsshd")
set(SSH_CLIENT_FILE_NAME "vssh")

set(SSH_SERVER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/vsshd/daemon/daemon.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vsshd/vsshd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vsshd/server/server_tcp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vsshd/server/server_udp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vsshd/server/terminal.c
    ${CMAKE_CURRENT_SOURCE_DIR}/utils/utils.c
)

set(SSH_CLIENT_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/vssh/vssh.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vssh/vssh_opts.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vssh/vssh_ctl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/utils/utils.c
)

# EXECUTABLE FILE
add_executable(${SSH_SERVER_FILE_NAME} ${SSH_SERVER_SOURCES})
add_executable(${SSH_CLIENT_FILE_NAME} ${SSH_CLIENT_SOURCES})

target_include_directories(${SSH_SERVER_FILE_NAME} PRIVATE net PRIVATE utils PRIVATE ipv4_net ipv4_net/udt/include vsshd/server vsshd/daemon)
target_include_directories(${SSH_CLIENT_FILE_NAME} PRIVATE net PRIVATE utils PRIVATE ipv4_net ipv4_net/udt/include)

target_link_libraries(${SSH_SERVER_FILE_NAME} ${IPV4NET_LIB_NAME})
target_link_libraries(${SSH_CLIENT_FILE_NAME} ${IPV4NET_LIB_NAME})

#########################################################################
