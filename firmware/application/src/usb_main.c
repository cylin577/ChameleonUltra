#include "usb_main.h"
#include "syssleep.h"
#include "dataframe.h"
#if CONFIG_STANDALONE_GDB_GATEWAY
#include "gdb_rsp.h"
#endif

#include "app_usbd.h"
#include "app_usbd_cdc_acm.h"
#include "app_usbd_core.h"
#include "app_usbd_serial_num.h"
#include "app_usbd_string_desc.h"
#include "nrf_strerror.h"
#if CONFIG_STANDALONE_U2F
#include "app_usbd_hid.h"
#include "app_usbd_hid_generic.h"
#include "standalone_modes/fido2_hid.h"
#endif

#define NRF_LOG_MODULE_NAME usb_cdc
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
NRF_LOG_MODULE_REGISTER();

// USB DEFINES START
static void cdc_acm_user_ev_handler(app_usbd_class_inst_t const *p_inst, app_usbd_cdc_acm_user_event_t event);

#define CDC_ACM_COMM_INTERFACE 0
#define CDC_ACM_COMM_EPIN NRF_DRV_USBD_EPIN2

#define CDC_ACM_DATA_INTERFACE 1
#define CDC_ACM_DATA_EPIN NRF_DRV_USBD_EPIN1
#define CDC_ACM_DATA_EPOUT NRF_DRV_USBD_EPOUT1

/** @brief CDC_ACM class instance */
APP_USBD_CDC_ACM_GLOBAL_DEF(m_app_cdc_acm,
                            cdc_acm_user_ev_handler,
                            CDC_ACM_COMM_INTERFACE,
                            CDC_ACM_DATA_INTERFACE,
                            CDC_ACM_COMM_EPIN,
                            CDC_ACM_DATA_EPIN,
                            CDC_ACM_DATA_EPOUT,
                            APP_USBD_CDC_COMM_PROTOCOL_AT_V250);

// USB DEFINES END

#if CONFIG_STANDALONE_U2F
// FIDO2 CTAPHID interface: usage page 0xF1D0, one 64-byte IN report and one
// 64-byte OUT report, no report id. The CDC keeps interfaces 0/1, so the HID
// gets interface 2 with its own endpoint pair.
#define HID_FIDO_INTERFACE   2
#define HID_FIDO_EPIN        NRF_DRV_USBD_EPIN3
#define HID_FIDO_EPOUT       NRF_DRV_USBD_EPOUT3
#define HID_FIDO_REPORT_SIZE 64
#define HID_FIDO_IN_QUEUE    4

APP_USBD_HID_GENERIC_SUBCLASS_REPORT_DESC(hid_fido_report_desc,
    {0x06, 0xD0, 0xF1,
     0x09, 0x01,
     0xA1, 0x01,
     0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02,
     0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02,
     0xC0});

static void hid_user_ev_handler(app_usbd_class_inst_t const *p_inst, app_usbd_hid_user_event_t event);
static const app_usbd_hid_subclass_desc_t *hid_fido_reports[] = {&hid_fido_report_desc};

APP_USBD_HID_GENERIC_GLOBAL_DEF(m_app_hid_generic,
                                HID_FIDO_INTERFACE,
                                hid_user_ev_handler,
                                (HID_FIDO_EPIN, HID_FIDO_EPOUT),
                                hid_fido_reports,
                                HID_FIDO_IN_QUEUE,
                                HID_FIDO_REPORT_SIZE - 1,  /* OUT buffer = maxsize + 1 */
                                0,                         /* no feature report */
                                APP_USBD_HID_SUBCLASS_NONE,
                                APP_USBD_HID_PROTO_GENERIC);

/* The GLOBAL_DEF macro leaves the IN report buffer uninitialised — point it
 * at a valid 64-byte buffer before the class is used. */
static uint8_t m_hid_in_buf[HID_FIDO_REPORT_SIZE];

static bool hid_fido_send(const uint8_t *pkt, size_t len) {
    ret_code_t err = app_usbd_hid_generic_in_report_set(&m_app_hid_generic, pkt, len);
    return err == NRF_SUCCESS;
}

static void hid_user_ev_handler(app_usbd_class_inst_t const *p_inst, app_usbd_hid_user_event_t event) {
    (void)p_inst;
    switch (event) {
        case APP_USBD_HID_USER_EVT_OUT_REPORT_READY: {
            size_t size = 0;
            const void *pkt = app_usbd_hid_generic_out_report_get(&m_app_hid_generic, &size);
            if (pkt && size >= HID_FIDO_REPORT_SIZE) {
                fido2_hid_on_out_report((const uint8_t *)pkt, HID_FIDO_REPORT_SIZE);
            }
            break;
        }
        case APP_USBD_HID_USER_EVT_IN_REPORT_DONE:
            fido2_hid_on_in_report_done();
            break;
        default:
            break;
    }
}
#endif /* CONFIG_STANDALONE_U2F */

// USB CODE START
volatile bool g_usb_connected = false;
volatile bool g_usb_port_opened = false;
volatile bool g_usb_led_marquee_enable = true;
static uint8_t cdc_data_buffer[NRF_DRV_USBD_EPSIZE];

/** @brief User event handler @ref app_usbd_cdc_acm_user_ev_handler_t */
static void cdc_acm_user_ev_handler(app_usbd_class_inst_t const *p_inst, app_usbd_cdc_acm_user_event_t event) {

    // app_usbd_cdc_acm_t const *p_cdc_acm = app_usbd_cdc_acm_class_get(p_inst);

    switch (event) {
        case APP_USBD_CDC_ACM_USER_EVT_PORT_OPEN: {
            // Setup first transfer
            ret_code_t ret = app_usbd_cdc_acm_read_any(&m_app_cdc_acm, cdc_data_buffer, sizeof(cdc_data_buffer));
            UNUSED_VARIABLE(ret);

            NRF_LOG_INFO("CDC ACM port opened");
            g_usb_port_opened = true;
            break;
        }

        case APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE:
            NRF_LOG_INFO("CDC ACM port closed");
            g_usb_port_opened = false;
            g_usb_led_marquee_enable = true;
            break;

        case APP_USBD_CDC_ACM_USER_EVT_TX_DONE:
            break;

        case APP_USBD_CDC_ACM_USER_EVT_RX_DONE: {
            // Get amount of data transfered to process data
            size_t size = app_usbd_cdc_acm_rx_size(&m_app_cdc_acm);
#if CONFIG_STANDALONE_GDB_GATEWAY
            // When the gdb_gateway standalone mode is armed the CDC link speaks
            // GDB RSP, not the framed CLI protocol; route bytes accordingly.
            if (gdb_rsp_active()) {
                gdb_rsp_rx(cdc_data_buffer, size);
            } else
#endif
            {
                data_frame_receive(cdc_data_buffer, size);
            }

            // Setup next transfer
            ret_code_t ret = app_usbd_cdc_acm_read_any(&m_app_cdc_acm, cdc_data_buffer, sizeof(cdc_data_buffer));
            UNUSED_VARIABLE(ret);
            break;
        }
        default:
            break;
    }
}

static void usbd_user_ev_handler(app_usbd_event_type_t event) {
    switch (event) {
        case APP_USBD_EVT_DRV_SUSPEND:
            NRF_LOG_INFO("USB SUSPEND");
            break;

        case APP_USBD_EVT_DRV_RESUME:
            NRF_LOG_INFO("USB RESUME");
            break;

        case APP_USBD_EVT_STARTED:
            NRF_LOG_INFO("USB STARTED");
            break;

        case APP_USBD_EVT_STOPPED:
            NRF_LOG_INFO("USB STOPPED");
            app_usbd_disable();
            break;

        case APP_USBD_EVT_POWER_DETECTED:
            sleep_timer_stop();
            NRF_LOG_INFO("USB power detected");
            if (!nrf_drv_usbd_is_enabled()) {
                app_usbd_enable();
            }
            g_usb_led_marquee_enable = true;
            break;

        case APP_USBD_EVT_POWER_REMOVED:
            sleep_timer_start(SLEEP_DELAY_MS_USB_POWER_DISCONNECTED);
            NRF_LOG_INFO("USB power removed");
            g_usb_connected = false;
            g_usb_led_marquee_enable = false;
            app_usbd_stop();
            break;

        case APP_USBD_EVT_POWER_READY:
            NRF_LOG_INFO("USB ready");
            g_usb_connected = true;
            app_usbd_start();
            break;

        default:
            // NRF_LOG_INFO("Other usb event: %d", event);
            break;
    }
}

// USB CODE END

void usb_cdc_init(void) {
    ret_code_t ret;
    static const app_usbd_config_t usbd_config = {
        .ev_state_proc = usbd_user_ev_handler
    };

    app_usbd_serial_num_generate();

    ret = app_usbd_init(&usbd_config);
    APP_ERROR_CHECK(ret);

    app_usbd_class_inst_t const *class_cdc_acm = app_usbd_cdc_acm_class_inst_get(&m_app_cdc_acm);
    ret = app_usbd_class_append(class_cdc_acm);
    APP_ERROR_CHECK(ret);

#if CONFIG_STANDALONE_U2F
    /* FIDO2 CTAPHID class (USB interface 2). The USB transport is optional:
     * if the class cannot be attached (e.g. no free endpoints) the device
     * must still boot — only the USB FIDO transport is lost. */
    m_app_hid_generic_in.p_buff = m_hid_in_buf;
    m_app_hid_generic_in.size = sizeof(m_hid_in_buf);
    app_usbd_class_inst_t const *class_hid = app_usbd_hid_generic_class_inst_get(&m_app_hid_generic);
    ret = app_usbd_class_append(class_hid);
    if (ret != NRF_SUCCESS) {
        NRF_LOG_ERROR("FIDO HID class not attached: %s", nrf_strerror_get(ret));
        fido2_hid_set_sender(NULL);       /* no USB FIDO transport */
    } else {
        fido2_hid_set_sender(hid_fido_send);
    }
#endif
}

void usb_cdc_write(const void *p_buf, uint16_t length) {
    ret_code_t err_code = app_usbd_cdc_acm_write(&m_app_cdc_acm, p_buf, length);
    APP_ERROR_CHECK(err_code);
}

// override fputc to printf to cdc serial
/* dont't enable
int fputc(int ch, FILE *f){
    static int ch_static;
    ch_static = ch;

    // must cdc is available
    if (g_usb_port_opened && g_usb_connected) {
        // send and wait done.
        ret_code_t ret;
        do {
            ret = app_usbd_cdc_acm_write(&m_app_cdc_acm, &ch_static, 1);
        } while(ret == NRF_ERROR_BUSY);

        // error log
        if (ret != NRF_SUCCESS) {
            NRF_LOG_ERROR("CDC ACM Unavailable, fputc: %c, return code: %d", ch_static, ret);
        }
    }

    return ch;
}
*/

bool is_usb_working(void) {
    return g_usb_port_opened;
}

void usb_power_events_enable(void) {
    APP_ERROR_CHECK(app_usbd_power_events_enable());
}

void usb_poll(void) {
    while (app_usbd_event_queue_process());
}
