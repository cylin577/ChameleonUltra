/*
 * app_error_check.h — keep the source location in fatal error reports.
 *
 * Outside DEBUG the SDK's APP_ERROR_HANDLER calls app_error_handler_bare(),
 * which throws away __FILE__ and __LINE__ — a crash log then only shows the
 * error code. The GCC variant app_error_handler() (app_error_handler_gcc.c,
 * compiled into this target) does keep them, so point APP_ERROR_HANDLER at
 * it: the fatal path is unchanged (app_error_fault_handler -> log ->
 * reset), it just carries the file and line of the failing check.
 *
 * app_error.h is included FIRST on purpose: its include guard then makes
 * the later #include "app_error.h" in any source file a no-op, so this
 * override cannot be silently overwritten.
 */
#ifndef APP_ERROR_CHECK_H
#define APP_ERROR_CHECK_H

#include "app_error.h"

#undef APP_ERROR_HANDLER
#define APP_ERROR_HANDLER(ERR_CODE)                                    \
    do                                                                 \
    {                                                                  \
        app_error_handler((ERR_CODE), __LINE__, (uint8_t *)__FILE__);  \
    } while (0)

#endif /* APP_ERROR_CHECK_H */
