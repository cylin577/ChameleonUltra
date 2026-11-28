/* Per-transport registry for CTAP status/keepalive callbacks. */
#include "fido2/fido2_transport.h"

static const fido2_transport_api_t *m_transports[FIDO2_TRANSPORT_DBG + 1];

void f2_transport_register(const fido2_transport_api_t *api)
{
    if (api == NULL || (unsigned)api->id > (unsigned)FIDO2_TRANSPORT_DBG) return;
    m_transports[api->id] = api;
}

const fido2_transport_api_t *f2_transport_get(fido2_transport_t id)
{
    if ((unsigned)id > (unsigned)FIDO2_TRANSPORT_DBG) return NULL;
    return m_transports[id];
}

void f2_transport_keepalive(uint8_t status)
{
    for (unsigned i = 0u; i <= (unsigned)FIDO2_TRANSPORT_DBG; i++) {
        const fido2_transport_api_t *api = m_transports[i];
        if (api != NULL && api->keepalive != NULL) api->keepalive(status);
    }
}
