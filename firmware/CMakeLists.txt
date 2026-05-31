cmake_minimum_required(VERSION 3.20)

# Toolchain must be set before project().
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/cmake/arm-none-eabi-toolchain.cmake
    CACHE FILEPATH "ARM bare-metal toolchain")

project(openhsm_fw C ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
set(VENDOR    ${CMAKE_CURRENT_SOURCE_DIR}/vendor)
set(CMSIS     ${VENDOR}/cmsis_core/CMSIS/Core/Include)
set(DEVICE    ${VENDOR}/cmsis_device_u5)
set(HAL       ${VENDOR}/stm32u5xx_hal)
set(USBLIB    ${VENDOR}/usb_device/Core)

set(LINKER_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/linker/STM32U585xx_flat.ld)

# ---------------------------------------------------------------------------
# MCU / compile flags
# ---------------------------------------------------------------------------
set(MCU_FLAGS -mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=hard)

add_compile_options(${MCU_FLAGS}
    -Wall -Wextra
    -ffunction-sections -fdata-sections
    $<$<CONFIG:Debug>:-Og> $<$<CONFIG:Debug>:-g3>
    $<$<CONFIG:Release>:-Os>)

add_compile_definitions(STM32U585xx USE_HAL_DRIVER)

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
set(HAL_SRC
    ${HAL}/Src/stm32u5xx_hal.c
    ${HAL}/Src/stm32u5xx_hal_cortex.c
    ${HAL}/Src/stm32u5xx_hal_rcc.c
    ${HAL}/Src/stm32u5xx_hal_rcc_ex.c
    ${HAL}/Src/stm32u5xx_hal_gpio.c
    ${HAL}/Src/stm32u5xx_hal_pwr.c
    ${HAL}/Src/stm32u5xx_hal_pwr_ex.c
    ${HAL}/Src/stm32u5xx_hal_flash.c
    ${HAL}/Src/stm32u5xx_hal_flash_ex.c
    ${HAL}/Src/stm32u5xx_hal_pcd.c
    ${HAL}/Src/stm32u5xx_hal_pcd_ex.c
    ${HAL}/Src/stm32u5xx_ll_usb.c
    ${HAL}/Src/stm32u5xx_hal_rng.c
    ${HAL}/Src/stm32u5xx_hal_cryp.c
    ${HAL}/Src/stm32u5xx_hal_cryp_ex.c
    ${HAL}/Src/stm32u5xx_hal_hash.c
    ${HAL}/Src/stm32u5xx_hal_hash_ex.c)

set(USB_SRC
    ${USBLIB}/Src/usbd_core.c
    ${USBLIB}/Src/usbd_ctlreq.c
    ${USBLIB}/Src/usbd_ioreq.c)

set(APP_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/stm32u5xx_it.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/system_stm32u5xx.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/usb/usbd_conf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/usb/usbd_desc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/usb/usbd_vendor.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/usb/usb_device.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hsm/hsm_command.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hsm/hsm_rng.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hsm/hsm_session.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hsm/hsm_flash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hsm/hsm_keystore.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hsm/hsm_audit.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/hsm_hash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/hsm_aead.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/hsm_x25519.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/hsm_eddsa.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/hsm_crypto.c
    ${VENDOR}/monocypher/src/monocypher.c
    ${VENDOR}/monocypher/src/optional/monocypher-ed25519.c)

set(STARTUP ${CMAKE_CURRENT_SOURCE_DIR}/startup/startup_stm32u585xx.s)

add_executable(openhsm.elf ${APP_SRC} ${HAL_SRC} ${USB_SRC} ${STARTUP})

target_include_directories(openhsm.elf PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hsm
    ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto
    ${VENDOR}/monocypher/src
    ${VENDOR}/monocypher/src/optional
    ${CMSIS}
    ${DEVICE}/Include
    ${HAL}/Inc
    ${USBLIB}/Inc)

# ---------------------------------------------------------------------------
# Link
# ---------------------------------------------------------------------------
target_link_options(openhsm.elf PRIVATE
    ${MCU_FLAGS}
    -T${LINKER_SCRIPT}
    --specs=nano.specs
    --specs=nosys.specs
    -Wl,--gc-sections
    -Wl,-Map=${CMAKE_BINARY_DIR}/openhsm.map,--cref
    -Wl,--print-memory-usage)

set_target_properties(openhsm.elf PROPERTIES LINK_DEPENDS ${LINKER_SCRIPT})

# ---------------------------------------------------------------------------
# Post-build: .bin / .hex + size
# ---------------------------------------------------------------------------
add_custom_command(TARGET openhsm.elf POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:openhsm.elf> ${CMAKE_BINARY_DIR}/openhsm.bin
    COMMAND ${CMAKE_OBJCOPY} -O ihex   $<TARGET_FILE:openhsm.elf> ${CMAKE_BINARY_DIR}/openhsm.hex
    COMMAND ${CMAKE_SIZE} $<TARGET_FILE:openhsm.elf>
    COMMENT "Generating openhsm.bin / openhsm.hex")

# ---------------------------------------------------------------------------
# Flash via DFU (board in system bootloader: hold BOOT0 high at reset).
#   make flash   (or: cmake --build . --target flash)
# ---------------------------------------------------------------------------
add_custom_target(flash
    COMMAND dfu-util -a 0 -s 0x08000000:leave -D ${CMAKE_BINARY_DIR}/openhsm.bin
    DEPENDS openhsm.elf
    COMMENT "Flashing openhsm.bin over DFU @0x08000000")
