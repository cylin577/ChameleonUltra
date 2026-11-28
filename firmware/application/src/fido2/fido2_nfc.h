/* NFC (ISO14443-4 / ISO7816 APDU) CTAP transport for the FIDO2 standalone mode.
 * Plain C11; no SDK headers needed by includers. */
#ifndef FIDO2_NFC_H
#define FIDO2_NFC_H

#include <stdbool.h>

/* Call once at mode initialisation (resets transport state only). */
void f2_nfc_init(void);

/* Install/remove the NFCT handler. set_armed(true) owns the 14A handler until
 * set_armed(false) restores the slot's normal 14A-4 handler. */
void f2_nfc_set_armed(bool armed);

/* Call from the standalone mode tick: moves a completed APDU out of the ISR,
 * dispatches it to the core and stages the response for transmission. */
void f2_nfc_poll(void);

/* True while this transport owns the NFCT handler. */
bool f2_nfc_available(void);

#endif /* FIDO2_NFC_H */
