/* Host test for the tick -> millisecond conversion used by the field detector.
 * The app-timer counter is a raw 24-bit RTC count (16384 Hz on this build),
 * not milliseconds; wiring it in unconverted would make 20 ms/100 ms windows
 * about 60x too short. */
#include "../bsp/bsp_time.h"

#include <stdio.h>

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)

#define RTC_TICKS_PER_SECOND 16384u

int main(void) {
    /* 1 s and the two detector thresholds. */
    CHECK(bsp_timer_ticks_to_ms(RTC_TICKS_PER_SECOND, RTC_TICKS_PER_SECOND) == 1000);
    CHECK(bsp_timer_ticks_to_ms(328, RTC_TICKS_PER_SECOND) == 20);   /* 20 ms */
    CHECK(bsp_timer_ticks_to_ms(1639, RTC_TICKS_PER_SECOND) == 100); /* 100 ms */

    /* Raw ticks are not ms: 16384 ticks must read 1000 ms, not 16384. */
    CHECK(bsp_timer_ticks_to_ms(16384, RTC_TICKS_PER_SECOND) != 16384);

    /* The 24-bit RTC wraps at 1024000 ms, which still fits in uint32_t so the
     * detector's unsigned subtraction stays wrap-safe. */
    CHECK(bsp_timer_ticks_to_ms(0x00FFFFFFu, RTC_TICKS_PER_SECOND) == 1023999);
    CHECK(bsp_timer_ticks_to_ms(0u, RTC_TICKS_PER_SECOND) == 0);
    CHECK(bsp_timer_ticks_to_ms(1000, 0) == 0);  /* no division by zero */

    printf("test_bsp_timer_ms: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
