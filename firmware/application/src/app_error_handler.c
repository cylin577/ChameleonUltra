/*
 * app_error_handler.c — fatal error reporting.
 *
 * The SDK ships a weak app_error_fault_handler that only prints "Fatal error"
 * in release builds (DEBUG is not defined), so a crash gave no clue about its
 * cause. This strong override prints the fault id, the program counter and
 * the error code (with its text) before the device resets, so the next crash
 * is diagnosable from the log alone.
 */
#include "app_error.h"

#include "app_util_platform.h"
#include "nrf_strerror.h"

#define NRF_LOG_MODULE_NAME app_error
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
NRF_LOG_MODULE_REGISTER();

void app_error_fault_handler(uint32_t id, uint32_t pc, uint32_t info)
{
    __disable_irq();
    NRF_LOG_FINAL_FLUSH();

    NRF_LOG_ERROR("FATAL fault id=0x%08x pc=0x%08x", id, pc);

    if (id == NRF_FAULT_ID_SDK_ERROR) {
        error_info_t const *p_info = (error_info_t const *)info;
        if (p_info != NULL) {
            if (p_info->p_file_name != NULL) {
                NRF_LOG_ERROR("ERROR %u [%s] at %s:%u",
                              p_info->err_code,
                              nrf_strerror_get(p_info->err_code),
                              (const char *)p_info->p_file_name,
                              p_info->line_num);
            } else {
                /* Release builds go through app_error_handler_bare(), which
                 * has no file/line information. */
                NRF_LOG_ERROR("ERROR %u [%s]",
                              p_info->err_code,
                              nrf_strerror_get(p_info->err_code));
            }
        }
    } else if (id == NRF_FAULT_ID_SDK_ASSERT) {
        assert_info_t const *p_info = (assert_info_t const *)info;
        if (p_info != NULL) {
            NRF_LOG_ERROR("ASSERT at %s:%u",
                          p_info->p_file_name ? (const char *)p_info->p_file_name : "?",
                          p_info->line_num);
        }
    }

    NRF_LOG_FINAL_FLUSH();
    NRF_BREAKPOINT_COND;

    // On a fault the system can only recover with a reset.
    NVIC_SystemReset();
}
