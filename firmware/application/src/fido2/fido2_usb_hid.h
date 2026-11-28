/* CTAPHID over the Nordic generic HID class. FIDO2 standalone mode only. */
#ifndef FIDO2_USB_HID_H
#define FIDO2_USB_HID_H

#include <stdbool.h>

/* Append the HID class instance. Called from usb_cdc_init() after CDC. */
void f2_usb_hid_init(void);

/* While disarmed, CTAP commands are ignored (INIT and PING still answer). */
void f2_usb_hid_set_armed(bool armed);

/* Main-loop pump: dispatch a completed request, then submit queued IN reports. */
void f2_usb_hid_poll(void);

/* True when app_usbd_class_append() accepted the HID instance. */
bool f2_usb_hid_available(void);

#endif /* FIDO2_USB_HID_H */
