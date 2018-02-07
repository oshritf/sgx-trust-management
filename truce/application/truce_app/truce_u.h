#ifndef _TRUCE_H
#define _TRUCE_H

#include "sgx_eid.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct _truce_session {
    sgx_enclave_id_t enclave_id;
    uint32_t truce_id_length;
    uint8_t *truce_id;
}truce_session_t;

typedef struct _truce_config {
    char *truce_server_address;
    char *seal_path = nullptr;
}truce_config_t;

int truce_session(sgx_enclave_id_t enclave_id, truce_config_t config, truce_session_t *truce_session);

int truce_add_secret(truce_session_t t_session, uint8_t* secret_buf, uint32_t secret_buf_size);



#ifdef  __cplusplus
}
#endif

#endif


