#########################################################################

# CMAKE MINIMAL VERSION
cmake_minimum_required (VERSION 3.8)

# PROJECT PROPERTIES
project ("List seminar" LANGUAGES C)

#########################################################################

# ASSEMBLY OPTIONS

if(NOT CMAKE_C_EXTENSIONS)
    set(CMAKE_C_EXTENSIONS OFF)
endif()

add_compile_options(
    -Wall
    -Wextra
)

#########################################################################

# TEST STUFF

set(LIST_TEST_NAME "list_test")

add_executable(${LIST_TEST_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/main.c)
target_link_libraries(${LIST_TEST_NAME} PRIVATE ${LIST_LIBRARY_NAME})

#########################################################################
