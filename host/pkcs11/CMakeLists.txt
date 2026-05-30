cmake_minimum_required(VERSION 3.20)
project(openhsm_pkcs11 C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUSB REQUIRED libusb-1.0)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)

# Shared PKCS#11 provider module.
add_library(openhsm_pkcs11 SHARED
    openhsm_pkcs11.c
    openhsm_transport.c)

target_include_directories(openhsm_pkcs11 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LIBUSB_INCLUDE_DIRS}
    ${LIBSODIUM_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../firmware/src/hsm)  # hsm_proto.h

target_link_directories(openhsm_pkcs11 PRIVATE ${LIBUSB_LIBRARY_DIRS} ${LIBSODIUM_LIBRARY_DIRS})
target_link_libraries(openhsm_pkcs11 PRIVATE ${LIBUSB_LIBRARIES} ${LIBSODIUM_LIBRARIES})
target_compile_options(openhsm_pkcs11 PRIVATE -Wall -Wextra ${LIBUSB_CFLAGS_OTHER})

# Development test harness (dlopen-based).
add_executable(p11test p11test.c)
target_include_directories(p11test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(p11test PRIVATE ${CMAKE_DL_LIBS})
target_compile_options(p11test PRIVATE -Wall -Wextra)

# One-shot key provisioning helper.
add_executable(p11provision p11provision.c)
target_include_directories(p11provision PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(p11provision PRIVATE ${CMAKE_DL_LIBS})
target_compile_options(p11provision PRIVATE -Wall -Wextra)
