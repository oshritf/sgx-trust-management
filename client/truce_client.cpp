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

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 

#include <openssl/rsa.h>
#include <curl/curl.h>

#include "truce_client.h"
#include "IAS_report_verifier.h"


FILE* OUTPUT =  stdout;

const char* truceServerAddress;


void print_string(const char* str) {
    fprintf(OUTPUT, "%s", str);
}


bool truce_client_init(const char* truce_server_address) {
    truceServerAddress = truce_server_address;

    // TODO: we call curl_global_init since for some reason, it makes verify_cert_chain to work.
    // It might be cause due to some memory leak, or for some good reason. We should investigate it.
    curl_global_init(CURL_GLOBAL_DEFAULT);

    return true;
}


bool truce_client_recv_enclave_record(
        const truce_id_t &t_id,
        truce_record_t &t_rec)
{

    if (NULL == truceServerAddress) {
        fprintf(OUTPUT, "ERROR: client not initialized with TruCE server address\n");
        return false;
    }

    // Create connection to TruCE server

    int sockfd = -1;
    char *ias_report_body = NULL;
    char *ias_report_signature_base64 = NULL;
    char *ias_report_cert_chain_urlsafe_pem = NULL;
    uint8_t *public_keys = NULL;
    uint32_t public_keys_size = 0;
    int len = 0;
    bool ret = false;
    int tmp_int = 0;
    uint8_t match_result = 0;

    if (!inet_connect(sockfd, truceServerAddress, SP_CS_PORT)) {
        fprintf(OUTPUT, "ERROR: connecting to TruCE server (%s:%d) has failed\n", 
            truceServerAddress, SP_CS_PORT);
        return false;
    }

    fprintf(OUTPUT, "Connected to TruCE server\n");

    // Sending t_id
    //fprintf(OUTPUT, "Sending t_id...\n");
    if (!write_all(sockfd, (uint8_t *) &t_id, sizeof(t_id))) {
        fprintf( OUTPUT, "ERROR: failed to send t_id\n");
        goto cleanup;
    }

    // Receiving search result
    //fprintf(OUTPUT, "Receiving match result...\n");
    if (1 != read(sockfd, &match_result, 1)) {
        fprintf( OUTPUT, "ERROR: failed to read match_result\n");
        goto cleanup;
    }

    if (match_result != 1) {
        fprintf( OUTPUT, "Warning: No enclave was found\n");
        goto cleanup;
    }

    // Receiving IAS_report_body length
    //fprintf(OUTPUT, "Receiving the size of IAS_report_body...\n");
    if (!read_all(sockfd, (uint8_t *) &tmp_int, 4)) {
        fprintf( OUTPUT, "ERROR: missing bytes for IAS_report_body length\n");
        goto cleanup;
    }
    len = ntohl(tmp_int);
    // Receiving IAS_report_body
    fprintf(OUTPUT, "Receiving %u bytes of IAS_report_body...\n", len);
    ias_report_body = (char *) calloc(1,len+1);
    if (NULL == ias_report_body) {
        fprintf( OUTPUT, "ERROR: failed to allocated %d byte for ias_report_body\n", len);
        goto cleanup;
    }
    if (!read_all(sockfd, (uint8_t *) ias_report_body, len)) {
        fprintf( OUTPUT, "ERROR: missing bytes for ias_report_body\n");
        goto cleanup;
    }


    // Receiving IAS_report_signature_base64 length
    //fprintf(OUTPUT, "Receiving the size of IAS_report_signature_base64...\n");
    if (!read_all(sockfd, (uint8_t *) &tmp_int, 4)) {
        fprintf( OUTPUT, "ERROR: missing bytes for IAS_report_signature_base64 length\n");
        goto cleanup;
    }
    len = ntohl(tmp_int);
    // Receiving IAS_report_signature_base64
    fprintf(OUTPUT, "Receiving %u bytes of ias_report_signature_base64...\n", len);
    ias_report_signature_base64 = (char *) calloc(1,len+1);
    if (NULL == ias_report_signature_base64) {
        fprintf( OUTPUT, "ERROR: failed to allocated %d byte for ias_report_signature_base64\n", len+1);
        goto cleanup;
    }
    if (!read_all(sockfd, (uint8_t *) ias_report_signature_base64, len)) {
        fprintf( OUTPUT, "ERROR: missing bytes for ias_report_signature_base64\n");
        goto cleanup;
    }


    // Receiving IAS_report_cert_chain_urlsafe_pem length
    //fprintf(OUTPUT, "Receiving the size of IAS_report_cert_chain_urlsafe_pem...\n");
    if (!read_all(sockfd, (uint8_t *) &tmp_int, 4)) {
        fprintf( OUTPUT, "ERROR: missing bytes for IAS_report_cert_chain_urlsafe_pem length\n");
        goto cleanup;
    }
    len = ntohl(tmp_int);
    // Receiving IAS_report_cert_chain_urlsafe_pem
    fprintf(OUTPUT, "Receiving %u bytes of ias_report_cert_chain_urlsafe_pem...\n", len);
    ias_report_cert_chain_urlsafe_pem = (char *) calloc(1,len+1);
    if (NULL == ias_report_cert_chain_urlsafe_pem) {
        fprintf( OUTPUT, "ERROR: failed to allocated %d byte for ias_report_cert_chain_urlsafe_pem\n", len+1);
        goto cleanup;
    }
    if (!read_all(sockfd, (uint8_t *) ias_report_cert_chain_urlsafe_pem, len)) {
        fprintf( OUTPUT, "ERROR: missing bytes for ias_report_cert_chain_urlsafe_pem\n");
        goto cleanup;
    }

    // Receiving public_keys_size length
    //fprintf(OUTPUT, "Receiving the size of Enclave's Public Keys...\n");
    if (!read_all(sockfd, (uint8_t *) &tmp_int, 4)) {
        fprintf( OUTPUT, "ERROR: missing bytes for public_keys_size\n");
        goto cleanup;
    }
    public_keys_size = ntohl(tmp_int);

    // Receiving public_keys
    fprintf(OUTPUT, "Receiving %u bytes of Enclave's Public Keys...\n", public_keys_size);
    public_keys = (uint8_t *) calloc(1,public_keys_size);
    if (NULL == public_keys) {
        fprintf( OUTPUT, "ERROR: failed to allocated %d byte for public_keys\n", public_keys_size);
        goto cleanup;
    }
    if (!read_all(sockfd, public_keys, public_keys_size)) {
        fprintf( OUTPUT, "ERROR: missing bytes for public_keys\n");
        goto cleanup;
    }

    t_rec.ias_report.report_body = ias_report_body;
    t_rec.ias_report.report_cert_chain_urlsafe_pem = ias_report_cert_chain_urlsafe_pem;
    t_rec.ias_report.report_signature_base64 = ias_report_signature_base64;
    t_rec.p_public_keys = (truce_public_keys_t *) public_keys;
    t_rec.public_keys_size = public_keys_size;
    
    ret = true;

    fprintf(OUTPUT, "Record has been received successfully!\n");

cleanup:

    if (sockfd != 0) {
        close(sockfd);
    }
    if (!ret) {
        if (ias_report_body != NULL) {
            free(ias_report_body);
        }
        if (ias_report_cert_chain_urlsafe_pem != NULL) {
            free(ias_report_cert_chain_urlsafe_pem);
        }
        if (ias_report_signature_base64 != NULL) {
            free(ias_report_signature_base64);
        }
        if (public_keys != NULL) {
            free(public_keys);
        }
    }

    return ret;
}


bool truce_client_extract_quote_from_record(
        const truce_record_t &t_rec,
        sgx_quote_t &quote) {

    return extract_quote_from_IAS_report(
            t_rec.ias_report,
            quote,
            print_string);
}



bool truce_client_verify_enclave_record(
        const truce_id_t &t_id,
        const truce_record_t &t_rec,
        const sgx_measurement_t &expected_mrenclave,
        const sgx_measurement_t &expected_mrsigner) {

    uint8_t sha_result[SHA256_DIGEST_LENGTH];

    // Verify that t_id == sha256(public_keys)
    SHA256((uint8_t *) t_rec.p_public_keys,
            t_rec.public_keys_size,
            (uint8_t *) &sha_result);

    if (memcmp((void *) &t_id, (void *) &sha_result, SHA256_DIGEST_LENGTH) != 0) {
        fprintf(OUTPUT, "t_id is different from sha256(public_keys).\n");
        return false;
    }

    return verify_IAS_report(
            t_rec.ias_report,
            expected_mrenclave,
            expected_mrsigner,
            (uint8_t *) t_rec.p_public_keys,
            t_rec.public_keys_size,
            print_string);

}


bool truce_client_encrypt_secret(
        const truce_record_t &t_rec,
        const uint8_t *secret,
        uint32_t secret_len,
        uint8_t *&output,
        uint32_t &output_size)
{
    RSA *pubkey_rsa = NULL;
    uint8_t *pubkey_rsa_tmp = NULL;
    uint32_t rsa_pubkey_len = t_rec.p_public_keys->rsa4096_public_key_size;
    bool ret = false;

    pubkey_rsa_tmp = (uint8_t *) calloc(1, rsa_pubkey_len);
    if (NULL == pubkey_rsa_tmp) {
        fprintf(OUTPUT, "ERROR: calloc has failed for pubkey_rsa_tmp\n");
        goto cleanup;
    }

    memcpy(pubkey_rsa_tmp, t_rec.p_public_keys->rsa4096_public_key, rsa_pubkey_len);
    pubkey_rsa = d2i_RSAPublicKey(0, (const unsigned char**)&pubkey_rsa_tmp, rsa_pubkey_len);
    if (NULL == pubkey_rsa) {
        fprintf(OUTPUT, "ERROR: d2i_RSAPublicKey has failed\n");
        goto cleanup;
    }

    output_size = RSA_size(pubkey_rsa);
    output = (uint8_t *) calloc(1,output_size);
    if (NULL == output) {
        fprintf(OUTPUT, "ERROR: failed to allocate %u bytes for output\n", output_size);
        goto cleanup;
    }

    if (output_size != RSA_public_encrypt(secret_len, secret, output, pubkey_rsa,
                                 RSA_PKCS1_PADDING)) {

        fprintf(OUTPUT, "ERROR: RSA_public_encrypt has failed\n");
        goto cleanup;
    }

    fprintf(OUTPUT, "Secret has been encrypted with enclave pub key. Len: %d\n", output_size);

    ret = true;

cleanup:

    /*if (pubkey_rsa_tmp != NULL) {
        free(pubkey_rsa_tmp);
    }*/
    if (pubkey_rsa != NULL) {
        RSA_free(pubkey_rsa);
    }

    if (!ret) {
        if (output != NULL) {
            free(output);
        }
        output_size = 0;
    }

    return ret;
}

