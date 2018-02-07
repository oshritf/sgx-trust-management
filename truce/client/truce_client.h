/*
 *
 * Licensed Materials - Property of IBM
 *
 * Copyright IBM Corp. 2017, 2017 All Rights Reserved
 *
 * US Government Users Restricted Rights - Use, duplication or
 * disclosure restricted by GSA ADP Schedule Contract with
 * IBM Corp.
 */

#include <stdint.h>

#include <openssl/rsa.h>

typedef struct _truce_enclave {
    uint8_t *truce_id;
    uint32_t truce_id_len;
    uint8_t *public_key;
    uint32_t public_key_len;
    uint8_t *mr_enclave;
    uint8_t *mr_signer;
    uint32_t mr_len;
    RSA* pubkey_rsa = NULL;
}truce_enclave_t;


int truce_client_get_enclave_record(const char* truce_server_address, uint8_t *truce_enc_id, int tid_len, truce_enclave_t *t_rec); 


int truce_client_get_mr_length(truce_enclave_t t_rec);


int truce_client_extract_mr_enclave(truce_enclave_t t_rec, uint8_t *mr_enc); 


int truce_client_extract_mr_signer(truce_enclave_t t_rec, uint8_t *mr_sig); 


int truce_client_get_pubkey_length(truce_enclave_t t_rec); 


int truce_client_extract_pubkey(truce_enclave_t t_rec, uint8_t *pubkey); 


int truce_client_encrypt_secret(truce_enclave_t t_enc, unsigned char *s_buf, uint8_t *secret, int secret_len);


