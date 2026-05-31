/**
 * @file    main.c
 * @brief   OpenHSM firmware entry point (Milestone 1: USB vendor + PING).
 *
 * Brings up the 160 MHz system clock + HSI48/CRS for USB, enumerates as a
 * USB vendor-specific device, and services HSM packets from the main loop.
 */
#include "main.h"
#include "usb_device.h"
#include "usbd_vendor.h"
#include "hsm_rng.h"
#include "hsm_crypto.h"
#include "hsm_session.h"
#include "hsm_keystore.h"
#include "hsm_audit.h"

static void led_init(void)
{
    GPIO_InitTypeDef gpio = {0};
    OPENHSM_LED_RCC_ENABLE();
    gpio.Pin   = OPENHSM_LED_PIN;
    gpio.Mode  = GPIO_MODE_OUTPUT_PP;
    gpio.Pull  = GPIO_NOPULL;
    gpio.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(OPENHSM_LED_PORT, &gpio);
}

void SystemClock_Config(void)
{
    RCC_OscInitTypeDef osc = {0};
    RCC_ClkInitTypeDef clk = {0};
    RCC_CRSInitTypeDef crs = {0};

    __HAL_RCC_PWR_CLK_ENABLE();

    /* 160 MHz operation requires voltage scaling range 1. */
    if (HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1) != HAL_OK) {
        Error_Handler();
    }

    /* HSI16 feeds the PLL (16 MHz); HSI48 feeds the USB/ICLK 48 MHz domain. */
    osc.OscillatorType      = RCC_OSCILLATORTYPE_HSI | RCC_OSCILLATORTYPE_HSI48;
    osc.HSIState            = RCC_HSI_ON;
    osc.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
    osc.HSI48State          = RCC_HSI48_ON;
    osc.PLL.PLLState        = RCC_PLL_ON;
    osc.PLL.PLLSource       = RCC_PLLSOURCE_HSI;
    osc.PLL.PLLM            = 1;
    osc.PLL.PLLMBOOST       = RCC_PLLMBOOST_DIV1;
    osc.PLL.PLLN            = 20;   /* 16 MHz * 20 = 320 MHz VCO */
    osc.PLL.PLLP            = 2;
    osc.PLL.PLLQ            = 2;
    osc.PLL.PLLR            = 2;    /* 320 / 2 = 160 MHz SYSCLK */
    osc.PLL.PLLRGE          = RCC_PLLVCIRANGE_1;
    osc.PLL.PLLFRACN        = 0;
    if (HAL_RCC_OscConfig(&osc) != HAL_OK) {
        Error_Handler();
    }

    clk.ClockType      = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK |
                         RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2 |
                         RCC_CLOCKTYPE_PCLK3;
    clk.SYSCLKSource   = RCC_SYSCLKSOURCE_PLLCLK;
    clk.AHBCLKDivider  = RCC_SYSCLK_DIV1;
    clk.APB1CLKDivider = RCC_HCLK_DIV1;
    clk.APB2CLKDivider = RCC_HCLK_DIV1;
    clk.APB3CLKDivider = RCC_HCLK_DIV1;
    if (HAL_RCC_ClockConfig(&clk, FLASH_LATENCY_4) != HAL_OK) {
        Error_Handler();
    }

    /* Auto-trim HSI48 against the USB Start-of-Frame for spec-compliant USB. */
    __HAL_RCC_CRS_CLK_ENABLE();
    crs.Prescaler             = RCC_CRS_SYNC_DIV1;
    crs.Source                = RCC_CRS_SYNC_SOURCE_USB;
    crs.Polarity              = RCC_CRS_SYNC_POLARITY_RISING;
    crs.ReloadValue           = RCC_CRS_RELOADVALUE_DEFAULT;
    crs.ErrorLimitValue       = RCC_CRS_ERRORLIMIT_DEFAULT;
    crs.HSI48CalibrationValue = RCC_CRS_HSI48CALIBRATION_DEFAULT;
    HAL_RCCEx_CRSConfig(&crs);
}

int main(void)
{
    HAL_Init();
    SystemClock_Config();

    led_init();
    HSM_Rng_Init();
    HSM_Crypto_Init();
    HSM_Session_Init();
    HSM_KeyStore_Init();
    HSM_Audit_Init();
    MX_USB_Device_Init();

    uint32_t last_blink = HAL_GetTick();

    for (;;) {
        USBD_Vendor_Poll(&hUsbDeviceFS);

        if ((HAL_GetTick() - last_blink) >= 250U) {
            last_blink = HAL_GetTick();
            HAL_GPIO_TogglePin(OPENHSM_LED_PORT, OPENHSM_LED_PIN);
        }
    }
}

void Error_Handler(void)
{
    __disable_irq();
    for (;;) {
        /* Halt: a debugger or power-cycle is required. */
    }
}

#ifdef USE_FULL_ASSERT
void assert_failed(uint8_t *file, uint32_t line)
{
    (void)file;
    (void)line;
    Error_Handler();
}
#endif
