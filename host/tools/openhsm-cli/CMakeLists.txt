cmake_minimum_required(VERSION 3.20)
project(openhsm_cli C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUSB REQUIRED libusb-1.0)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)

set(PKCS11DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../pkcs11)

add_executable(openhsm-cli
    main.c
    ${PKCS11DIR}/openhsm_transport.c)   # shared USB/TCP + secure-session transport

target_include_directories(openhsm-cli PRIVATE
    ${PKCS11DIR}
    ${LIBUSB_INCLUDE_DIRS}
    ${LIBSODIUM_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../firmware/src/hsm)  # hsm_proto.h

target_link_directories(openhsm-cli PRIVATE ${LIBUSB_LIBRARY_DIRS} ${LIBSODIUM_LIBRARY_DIRS})
target_link_libraries(openhsm-cli PRIVATE ${LIBUSB_LIBRARIES} ${LIBSODIUM_LIBRARIES})
target_compile_options(openhsm-cli PRIVATE -Wall -Wextra ${LIBUSB_CFLAGS_OTHER})
