#########################################################################

# CMAKE MINIMAL VERSION
cmake_minimum_required (VERSION 3.8)

# PROJECT PROPERTIES
project ("Socket seminar" LANGUAGES C)

#########################################################################

# EXECUTABLE FILE PROPERTIES
set(SERVER_FILE_NAME "server")
set(CLIENT_FILE_NAME "client")

set(HEADERS
        net.h
)

set(SERVER_SOURCES
        server.c
)

set(CLIENT_SOURCES
        client.c
)

# EXECUTABLE FILE
add_executable(${SERVER_FILE_NAME} ${SERVER_SOURCES})
add_executable(${CLIENT_FILE_NAME} ${CLIENT_SOURCES})

#########################################################################

# ASSEMBLY OPTIONS

if(NOT CMAKE_C_EXTENSIONS)
    set(CMAKE_C_EXTENSIONS OFF)
endif()

add_compile_options(
    -Werror

    -Wall
    -Wextra
    -Wpedantic
)

#########################################################################
