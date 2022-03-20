#########################################################################

# CMAKE MINIMAL VERSION
cmake_minimum_required (VERSION 3.8)

# PROJECT PROPERTIES
project ("Broadcast seminar" LANGUAGES C)

#########################################################################

# EXECUTABLE FILE PROPERTIES
set(RECEIVER_FILE_NAME "receiver")
set(SENDER_FILE_NAME "sender")

set(HEADERS
        net.h
)

set(RECEIVER_SOURCES
        broadcast_receiver.c
)

set(SENDER_SOURCES
        broadcast_sender.c
)

# EXECUTABLE FILE
add_executable(${RECEIVER_FILE_NAME} ${RECEIVER_SOURCES})
add_executable(${SENDER_FILE_NAME} ${SENDER_SOURCES})

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
