#ifndef MODE_FIDO2_H
#define MODE_FIDO2_H

#include <stdbool.h>

/* Grant both UP and UV from a raw physical button press while FIDO2 is armed. */
void mode_fido2_raw_press_grant(void);

#endif /* MODE_FIDO2_H */
