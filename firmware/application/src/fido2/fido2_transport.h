/* Transport callbacks used by the FIDO2 core. */
#ifndef FIDO2_TRANSPORT_H__
#define FIDO2_TRANSPORT_H__

#include <stddef.h>
#include <stdint.h>

#include "fido2/fido2_types.h"

typedef struct {
    fido2_transport_t id;
    void (*send)(const uint8_t *data, size_t len);   /* already framed by transport */
    void (*keepalive)(uint8_t status);               /* 0x02 processing, 0x03 UP needed */
} fido2_transport_api_t;

/* api must outlive the registration (usually a static object). A NULL send
   means the core will not push a timeout status by itself. */
void f2_transport_register(const fido2_transport_api_t *api);
const fido2_transport_api_t *f2_transport_get(fido2_transport_t id);
void f2_transport_keepalive(uint8_t status);   /* broadcast to all transports */

#endif /* FIDO2_TRANSPORT_H__ */
