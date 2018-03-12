/*
    * Licensed to the Apache Software Foundation (ASF) under one
    * or more contributor license agreements. See the NOTICE file
    * distributed with this work for additional information
    * regarding copyright ownership. The ASF licenses this file
    * to you under the Apache License, Version 2.0 (the
    * "License"); you may not use this file except in compliance
    * with the License. You may obtain a copy of the License at
    *
    * http://www.apache.org/licenses/LICENSE-2.0
    *
    * Unless required by applicable law or agreed to in writing,
    * software distributed under the License is distributed on an
    * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    * KIND, either express or implied. See the License for the
    * specific language governing permissions and limitations
    * under the License.
    */


#include <assert.h>
#include "truce_enclave_t.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include "sgx_utils.h"
#include "string.h"
#include "truce_t.h"
#include "truce_public_keys.h"
#include "truce_private_keys.h"
#include <stdio.h>  // for snprintf
#include <string.h>


#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>


#define  ENCLAVE_DEBUG_PRINT_PREFIX        "[SGX_ENCLAVE] "


static truce_public_keys_t     *g_public_keys     =     NULL;
static uint32_t                g_public_keys_size = 0;
static truce_private_keys_t *g_private_keys =     NULL;
static uint32_t                g_private_keys_size = 0;
static bool                 g_after_generate_keys    =    false;

static RSA *g_rsa = NULL;


void enclave_debug_print(const char *str) {
    /* TODO: change it. Add another ocall that gets two parameters. */
    ocall_print_string(ENCLAVE_DEBUG_PRINT_PREFIX);
    ocall_print_string(str);
}


truce_secret_t *Secret_head = NULL;
truce_secret_t *Secret_tail = NULL;



void print_buffer(uint8_t* buf, int len)
{
    char out[20];
    snprintf(out, 20, "Length: %d \n", len);
    ocall_print_string(out);
    for (int i=0; i < len; i++) {
        snprintf(out, 20, "0x%x ", buf[i]);
        ocall_print_string(out);
    }
    ocall_print_string("\n");
}



sgx_status_t ECALL_generate_keys() {

    sgx_status_t ret = SGX_SUCCESS;
    sgx_ecc_state_handle_t ecc_state = NULL;
    int retval = 0;
    BIGNUM    *bne = NULL;
    EVP_PKEY *evp_pkey = NULL;
    int rsa_pub_key_size = 0;
    int rsa_priv_key_size = 0;
    uint8_t *tmp_buf = NULL;

    if (g_after_generate_keys) {
        enclave_debug_print("ERROR: Keys have been already generated\n");
        return SGX_ERROR_INVALID_STATE;
    }

    /////////////////////////////   Creating RSA 4096 key pair with openssl.
    bne = BN_new();
    if (bne == NULL) {
        enclave_debug_print("ERROR: BN_new has failed\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }
    retval = BN_set_word(bne,RSA_F4);
    if (retval != 1) {
        enclave_debug_print("ERROR: BN_set_word has failed\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto cleanup;
    }
    g_rsa = RSA_new();
    if (NULL == g_rsa) {
        enclave_debug_print("ERROR: RSA_new has failed\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }
    retval = RSA_generate_key_ex(g_rsa, 4096, bne, NULL);
    if (retval != 1) {
        enclave_debug_print("ERROR: RSA_generate_key_ex has failed\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto cleanup;
    }
    evp_pkey = EVP_PKEY_new();
    if (evp_pkey == NULL) {
        enclave_debug_print("ERROR: EVP_PKEY_new has failed\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }
    EVP_PKEY_assign_RSA(evp_pkey, g_rsa);

    // extract RSA 4096 public key
    rsa_pub_key_size = i2d_PublicKey(evp_pkey, NULL);
    g_public_keys_size = sizeof(truce_public_keys_t) + rsa_pub_key_size;
    g_public_keys = (truce_public_keys_t *) calloc(1, g_public_keys_size);
    if (g_public_keys == NULL) {
        enclave_debug_print("ERROR: calloc for g_public_keys has failed\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }
    g_public_keys->rsa4096_public_key_size = rsa_pub_key_size;
    tmp_buf = (uint8_t *) &g_public_keys->rsa4096_public_key;
    i2d_PublicKey(evp_pkey, &tmp_buf);

    // extract RSA 4096 private key
    rsa_priv_key_size = i2d_PrivateKey(evp_pkey, NULL);
    g_private_keys_size = sizeof(truce_private_keys_t) + rsa_priv_key_size;
    g_private_keys = (truce_private_keys_t *) calloc(1, g_private_keys_size);
    if (g_private_keys == NULL) {
        enclave_debug_print("ERROR: calloc for g_private_keys has failed\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }
    g_private_keys->rsa4096_private_key_size = rsa_priv_key_size;
    tmp_buf = (uint8_t *) &g_private_keys->rsa4096_private_key;
    i2d_PrivateKey(evp_pkey, &tmp_buf);


    ///////////////////////////////////  Creating ec256 key pair with sgxsdk
    ret = sgx_ecc256_open_context(&ecc_state);
    if (SGX_SUCCESS != ret) {
        enclave_debug_print("ERROR: sgx_ecc256_open_context has failed.\n");
        goto cleanup;
    }

    ret = sgx_ecc256_create_key_pair(&g_private_keys->ec256_private_key, // a
            &g_public_keys->ec256_public_key, // g^a
            ecc_state);
    if (SGX_SUCCESS != ret) {
        enclave_debug_print("ERROR: sgx_ecc256_create_key_pair has failed.\n");
        goto cleanup;
    }

    ret = sgx_ecc256_close_context(ecc_state);
    if (SGX_SUCCESS != ret) {
        enclave_debug_print("ERROR: sgx_ecc256_close_context has failed.\n");
        goto cleanup;
    }
    g_after_generate_keys = true;

cleanup:

    if (bne != NULL) {
        BN_free(bne);
    }
    if (evp_pkey != NULL) {
        /* TBD: EVP_PKEY_free causes segfault.
                  Probably because it tries to free g_rsa again.
                  Verify that this indeed the case and we don't need to free evp_pkey.
                  Maybe we need to just call free in this case, and not EVP_PKEY_free. */
        /*EVP_PKEY_free(evp_pkey);*/
    }
    if (!g_after_generate_keys) {
        if (g_rsa != NULL) {
            RSA_free(g_rsa);
            g_rsa = NULL;
        }
        if (g_public_keys != NULL) {
            free(g_public_keys);
            g_public_keys = NULL;
        }
        if (g_private_keys != NULL) {
            free(g_private_keys);
            g_private_keys = NULL;
        }
    }
    return ret;
}


sgx_status_t ECALL_get_public_keys_size(uint32_t *pub_keys_size) {
    if (!g_after_generate_keys) {
        enclave_debug_print("Warning: ECALL_get_public_keys_size has failed since there is no public key.\n");
        return SGX_ERROR_INVALID_STATE;
    }

    *pub_keys_size = g_public_keys_size;
    return SGX_SUCCESS;
}

sgx_status_t ECALL_get_public_keys(uint8_t *p_public_keys,
                                      uint32_t pub_keys_size) {
    if (!g_after_generate_keys) {
        enclave_debug_print("Warning: ECALL_get_public_keys has failed since there is no public key.\n");
        return SGX_ERROR_INVALID_STATE;
    }
    if (pub_keys_size < g_public_keys_size) {
        enclave_debug_print("Warning: ECALL_get_public_keys has failed since pub_keys_size is too small.\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    memcpy(p_public_keys, (void *) g_public_keys, g_public_keys_size);
    return SGX_SUCCESS;
}


sgx_status_t ECALL_create_enclave_report(
                            const sgx_target_info_t *p_target_info, //in
                            sgx_report_t *p_report) { //out

    sgx_status_t ret = SGX_SUCCESS;
    sgx_report_data_t report_data = {{0}};

    if (!g_after_generate_keys) {
        enclave_debug_print("Warning: ECALL_create_enclave_report has failed since there is no public keys.\n");
        return SGX_ERROR_INVALID_STATE;
    }
    if (sizeof(sgx_report_data_t) < sizeof(sgx_sha256_hash_t)) {
        return SGX_ERROR_UNEXPECTED;
    }

    ret = sgx_sha256_msg((uint8_t *) g_public_keys,
            g_public_keys_size,
            (sgx_sha256_hash_t *) &report_data);

    if (ret != SGX_SUCCESS) {
        enclave_debug_print("ERROR: sgx_sha256_msg has failed.\n");
        return ret;
    }

    ret = sgx_create_report(p_target_info, &report_data, p_report);
    if (ret != SGX_SUCCESS) {
        enclave_debug_print("ERROR: sgx_create_report has failed.\n");
        return ret;
    }

    return ret;
}


bool get_seals_sizes(uint32_t &first_seal_size, uint32_t &second_seal_size) {

    if (!g_after_generate_keys) {
        enclave_debug_print("Warning: ECALL_get_sealed_keys_size has failed since there is no public keys.\n");
        return false;
    }
    // First Seal using MRSIGNER. The data is: (pub_key_size, pub_key, priv_key_size, priv_key)
    first_seal_size = sgx_calc_sealed_data_size(0,
            sizeof(uint32_t) + g_public_keys_size + sizeof(uint32_t) + g_private_keys_size);
    if (UINT32_MAX == first_seal_size) {
        enclave_debug_print("ERROR: first sgx_calc_sealed_data_size has failed.\n");
        return false;
    }
    second_seal_size = sgx_calc_sealed_data_size(0, first_seal_size); // Second seal using MRENCLAVE
    if (UINT32_MAX == second_seal_size) {
        enclave_debug_print("ERROR: first sgx_calc_sealed_data_size has failed.\n");
        return false;
    }
    return true;
}


sgx_status_t ECALL_get_sealed_keys_size(uint32_t *sealed_keys_size) {
    uint32_t first_seal_size = 0;
    uint32_t second_seal_size = 0;

    if (!get_seals_sizes(first_seal_size, second_seal_size)) {
        enclave_debug_print("ERROR: get_seals_sizes has failed.\n");
        return SGX_ERROR_INVALID_STATE;
    }

    *sealed_keys_size = second_seal_size;
    return SGX_SUCCESS;
}

sgx_status_t ECALL_seal_keys(uint8_t *sealed_keys,
                             uint32_t sealed_keys_size) {

    sgx_status_t ret = SGX_SUCCESS;
    uint32_t first_seal_size = 0;
    uint32_t second_seal_size = 0;
    uint8_t *data_to_seal = NULL;
    uint32_t data_to_seal_size = 0;
    uint8_t *tmp_ptr = NULL;
    uint8_t *first_seal = NULL;
    sgx_attributes_t attribute_mask;
    sgx_misc_select_t misc_mask = 0xF0000000;

    if (!g_after_generate_keys) {
        enclave_debug_print("Warning: ECALL_get_sealed_keys has failed since there is no public keys.\n");
        return SGX_ERROR_INVALID_STATE;
    }

    data_to_seal_size = sizeof(uint32_t) + g_public_keys_size +
                        sizeof(uint32_t) + g_private_keys_size;
    data_to_seal = (uint8_t *) malloc(data_to_seal_size);

    if (NULL == data_to_seal) {
        enclave_debug_print("ERROR: failed to allocate data_to_seal.\n");
        goto cleanup;
    }
    tmp_ptr = data_to_seal;

    memcpy(tmp_ptr, (void *) &g_public_keys_size, sizeof(uint32_t));
    tmp_ptr += sizeof(uint32_t);
    memcpy(tmp_ptr, (void *) g_public_keys, g_public_keys_size);
    tmp_ptr += g_public_keys_size;
    memcpy(tmp_ptr, (void *) &g_private_keys_size, sizeof(uint32_t));
    tmp_ptr += sizeof(uint32_t);
    memcpy(tmp_ptr, (void *) g_private_keys, g_private_keys_size);

    if (!get_seals_sizes(first_seal_size, second_seal_size)) {
        enclave_debug_print("ERROR: get_seals_sizes has failed.\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto cleanup;
    }

    if (sealed_keys_size < second_seal_size) {
        enclave_debug_print("ERROR: seal_keys_size is too small.\n");
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto cleanup;
    }

    first_seal = (uint8_t *) malloc(first_seal_size);
    if (NULL == first_seal) {
        enclave_debug_print("ERROR: failed to allocate first_seal.\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    // First, seal with key derived from MR_SIGNER
    ret = sgx_seal_data(0,NULL,data_to_seal_size, (uint8_t *) data_to_seal,
            first_seal_size, (sgx_sealed_data_t *) first_seal);

    if(ret != SGX_SUCCESS) {
        enclave_debug_print("ERROR: Failed to mr_signer-seal enclave keys\n");
        goto cleanup;
    }

    // Second, seal with key derived from MR_ENCLAVE
    attribute_mask.flags = 0xFF0000000000000B;
    attribute_mask.xfrm = 0;
    misc_mask = 0xF0000000;

    ret = sgx_seal_data_ex(0x0001, attribute_mask, misc_mask, 0,NULL,first_seal_size,
            first_seal, sealed_keys_size, (sgx_sealed_data_t *) sealed_keys);

    if(SGX_SUCCESS != ret) {
        enclave_debug_print("ERROR: Failed to mr_enclave-seal enclave keys\n");
        goto cleanup;
    }
    enclave_debug_print("Sealed enclave keys\n");

cleanup:

    if (data_to_seal != NULL) {
        free(data_to_seal);
    }
    if (first_seal != NULL) {
        free(first_seal);
    }

    return ret;
}


sgx_status_t ECALL_unseal_keys(
                            const uint8_t *sealed_keys,
                            uint32_t sealed_keys_size) {

    sgx_status_t ret = SGX_SUCCESS;
    uint32_t first_seal_size = 0;
    uint8_t *first_seal = NULL;
    uint32_t data_size = 0;
    uint8_t *data = NULL;
    uint8_t *tmp_buf = NULL;

    if (g_after_generate_keys) {
        enclave_debug_print("ERROR: Keys have been generated already\n");
        return SGX_ERROR_INVALID_STATE;
    }

    //// First, unseal the mr-enclave sealing
    first_seal_size = sgx_get_encrypt_txt_len((const _sealed_data_t *) sealed_keys);
    if (UINT32_MAX == first_seal_size) {
        enclave_debug_print("ERROR: first sgx_get_encrypt_txt_len has failed.\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto cleanup;
    }

    first_seal = (uint8_t *) malloc(first_seal_size);
    if (NULL == first_seal) {
        enclave_debug_print("ERROR: failed to allocate first_seal\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    ret = sgx_unseal_data((sgx_sealed_data_t *) sealed_keys, NULL, NULL,
            first_seal, &first_seal_size);

    if (ret != SGX_SUCCESS) {
        ocall_print_string("ERROR: Failed to unseal enclave key (step 1)\n");
        goto cleanup;
    }

    //// Second, unseal the mr-signer sealing
    data_size = sgx_get_encrypt_txt_len((const _sealed_data_t *) first_seal);
    if (UINT32_MAX == data_size) {
        enclave_debug_print("ERROR: second sgx_get_encrypt_txt_len has failed.\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto cleanup;
    }

    data = (uint8_t *) malloc(data_size);
    if (NULL == data) {
        enclave_debug_print("ERROR: failed to allocate keys\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    ret = sgx_unseal_data((sgx_sealed_data_t *) first_seal, NULL, NULL,
            data, &data_size);

    if (ret != SGX_SUCCESS) {
        ocall_print_string("ERROR: Failed to unseal enclave key (step 2)\n");
        goto cleanup;
    }

    //// Finally, Extract the keys from the data
    // Extract public keys
    tmp_buf = data;
    memcpy(&g_public_keys_size, (void *) tmp_buf, sizeof(uint32_t));
    tmp_buf += sizeof(uint32_t);
    g_public_keys = (truce_public_keys_t *) malloc(g_public_keys_size);
    if (NULL == g_public_keys) {
        enclave_debug_print("ERROR: failed to allocate g_public_keys\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }
    memcpy(g_public_keys, (void *) tmp_buf, g_public_keys_size);
    tmp_buf += g_public_keys_size;

    // Extract private keys
    memcpy(&g_private_keys_size, (void *) tmp_buf, sizeof(uint32_t));
    tmp_buf += sizeof(uint32_t);
    g_private_keys = (truce_private_keys_t *) malloc(g_private_keys_size);
    if (NULL == g_private_keys) {
        enclave_debug_print("ERROR: failed to allocate g_private_keys\n");
        ret = SGX_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }
    memcpy(g_private_keys, (void *) tmp_buf, g_private_keys_size);

    // restore g_rsa
    tmp_buf = (uint8_t *) g_private_keys->rsa4096_private_key;

    g_rsa = d2i_RSAPrivateKey(0, (const unsigned char**) &tmp_buf, g_private_keys->rsa4096_private_key_size);
    if (NULL == g_rsa) {
        enclave_debug_print("ERROR: d2i_RSAPrivateKey has failed\n");
        ret = SGX_ERROR_UNEXPECTED;
        goto cleanup;
    }

    g_after_generate_keys = true;

cleanup:

    if (first_seal != NULL) {
        free(first_seal);
    }

    if (!g_after_generate_keys) {
        if (g_public_keys != NULL) {
            free(g_public_keys);
            g_public_keys = NULL;
        }
        if (g_private_keys != NULL) {
            free(g_private_keys);
            g_private_keys = NULL;
        }
        if (g_rsa != NULL) {
            RSA_free(g_rsa);
            g_rsa = NULL;
        }
    }
    return ret;
}

// TODO: handle errors and consider to use c++ list.
sgx_status_t ECALL_add_secret(
    const uint8_t* secret_buf,
    uint32_t secret_buf_size)
{
    sgx_status_t ret = SGX_SUCCESS;

    unsigned char ptext[1000]; // TODO

    int num = RSA_private_decrypt(secret_buf_size, secret_buf, ptext,  g_rsa, RSA_PKCS1_PADDING);

    ocall_print_string("Enclave: got secret\n");
    //print_buffer(ptext, num);

    truce_secret_t *ptr = (truce_secret_t*)malloc(sizeof(truce_secret_t));
    ptr->secret = (unsigned char *) malloc (num);
    memcpy(ptr->secret, ptext, num);
    ptr->secret_len = num;
    ptr->next = NULL;

    if (NULL == Secret_head) {
        Secret_head = ptr;
        Secret_tail = ptr;
    }
    else {
        Secret_tail->next = ptr;
        Secret_tail = ptr;
    }

    return ret;
}

truce_secret_t *truce_get_secrets() {
    return Secret_head;
}

