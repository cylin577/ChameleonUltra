/* Host stub for the SDK's nrf_log.h — swallows the log calls so the
 * standalone framework can be unit-tested on the host. */
#ifndef STUB_NRF_LOG_H
#define STUB_NRF_LOG_H

static inline void test_log_sink(const char *fmt, ...) { (void)fmt; }

#define NRF_LOG_INFO(...)    test_log_sink(__VA_ARGS__)
#define NRF_LOG_WARNING(...) test_log_sink(__VA_ARGS__)
#define NRF_LOG_ERROR(...)   test_log_sink(__VA_ARGS__)
#define NRF_LOG_DEBUG(...)   test_log_sink(__VA_ARGS__)

#endif /* STUB_NRF_LOG_H */
