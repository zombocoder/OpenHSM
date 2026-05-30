cmake_minimum_required(VERSION 3.20)
project(openhsm_ping C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUSB REQUIRED libusb-1.0)

add_executable(openhsm-ping main.c)

target_include_directories(openhsm-ping PRIVATE
    ${LIBUSB_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../firmware/src/hsm)

target_link_directories(openhsm-ping PRIVATE ${LIBUSB_LIBRARY_DIRS})
target_link_libraries(openhsm-ping PRIVATE ${LIBUSB_LIBRARIES})
target_compile_options(openhsm-ping PRIVATE ${LIBUSB_CFLAGS_OTHER} -Wall -Wextra)
