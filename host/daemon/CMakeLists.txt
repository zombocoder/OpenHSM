cmake_minimum_required(VERSION 3.20)
project(openhsm_daemon C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUSB REQUIRED libusb-1.0)

add_executable(openhsm-daemon openhsm_daemon.c)
target_include_directories(openhsm-daemon PRIVATE
    ${LIBUSB_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../firmware/src/hsm)  # hsm_proto.h
target_link_directories(openhsm-daemon PRIVATE ${LIBUSB_LIBRARY_DIRS})
target_link_libraries(openhsm-daemon PRIVATE ${LIBUSB_LIBRARIES})
target_compile_options(openhsm-daemon PRIVATE -Wall -Wextra ${LIBUSB_CFLAGS_OTHER})
