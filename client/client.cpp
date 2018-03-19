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

#include "truce_client.h"
#include <string.h>
#include <unistd.h>


const char *g_secret1 = "This is my first secret";
const char *g_secret2 = "This is my second and longer secret";

int main(int argc, char* argv[])
{

    if (argc < 2) {
        printf("ERROR: Need IP address as argument\n");
        return 1;
    }
    const char* truce_server_address = argv[1];
    const char* agent_address = argv[2];

    if (NULL == agent_address) {
        agent_address = truce_server_address;
    }

    int tmp_int;
    truce_id_t t_id = {{0}};
    truce_record_t t_rec;
    sgx_measurement_t expected_mrenclave = {{0}}; // Should be the real value
    sgx_measurement_t expected_mrsigner = {{0}}; // Should be the real value
    uint8_t *encrypted_secret1 = NULL;
    uint32_t encrypted_secret1_size = 0;
    uint8_t *encrypted_secret2 = NULL;
    uint32_t encrypted_secret2_size = 0;
    sgx_quote_t quote = {0};
    int sockfd = -1;

    // Create TCP connection to agent/enclave. You can use any transport in your application.

    
    if (!inet_connect(sockfd, agent_address, 6000)) {
        printf("ERROR : failed to connect to the Application at %s:%d\n", truce_server_address, 6000);
        goto cleanup;
    }

    // Receive truce id
    if (!read_all(sockfd, (uint8_t *) &t_id, sizeof(t_id))) {
        printf("ERROR: failed to read %lu bytes of t_id\n", sizeof(t_id));
        goto cleanup;
    }

    printf("Received t_id:\n");
    print_buffer((uint8_t *) &t_id, sizeof(t_id));

    truce_client_init(truce_server_address);

    // Get the enclave record from TruCE server

    if (!truce_client_recv_enclave_record(t_id, t_rec)) {
        printf("ERROR: failed to receive truce record from truce server\n");
        goto cleanup;
    }

    // Verify enclave and signer measurements
    // TODO: At that point, the client should know what is the expected mrenclave and mrsigner.
    // for the simplicity of this code, we set the expected measurements to the given measurements.
    if (!truce_client_extract_quote_from_record(
                    t_rec,
                    quote)) {
        printf("ERROR: failed to extract quote from record\n");
        goto cleanup;
    }
    // TODO: should be calculated from a given SO file.
    memcpy((void *) &expected_mrenclave, (void *) &quote.report_body.mr_enclave, sizeof(sgx_measurement_t));
    memcpy((void *) &expected_mrsigner, (void *) &quote.report_body.mr_signer, sizeof(sgx_measurement_t));

    if (!truce_client_verify_enclave_record(
            t_id,
            t_rec,
            expected_mrenclave,
            expected_mrsigner)) {

        printf("ERROR: failed to verify enclave's record\n");
        goto cleanup;
    }

    // Encrypting secrets using Enclave's RSA public key.
    if (!truce_client_encrypt_secret(
            t_rec,
            (uint8_t *) g_secret1,
            strlen(g_secret1) + 1,
            encrypted_secret1,
            encrypted_secret1_size)) {

        printf("ERROR: failed to encrypt secret 1\n");
        goto cleanup;

    }

    if (!truce_client_encrypt_secret(
            t_rec,
            (uint8_t *) g_secret2,
            strlen(g_secret2) + 1,
            encrypted_secret2,
            encrypted_secret2_size)) {

        printf("ERROR: failed to encrypt secret 2\n");
        goto cleanup;

    }

    // send encrypted secret 1
    if (!write_all(sockfd, (uint8_t *) &encrypted_secret1_size, 4)) {
        printf("ERROR: failed to send encrypted_secret1_size\n");
        goto cleanup;
    }

    if (!write_all(sockfd, (uint8_t *) &encrypted_secret1, encrypted_secret1_size)) {
        printf("ERROR: failed to send %u bytes of encrypted_secret1\n", encrypted_secret1_size);
        goto cleanup;
    }
    
    // send encrypted secret 2
    if (!write_all(sockfd, (uint8_t *) &encrypted_secret2_size, 4)) {
        printf("ERROR: failed to send encrypted_secret2_size\n");
        goto cleanup;
    }
    
    if (!write_all(sockfd, (uint8_t *) &encrypted_secret2, encrypted_secret2_size)) {
        printf("ERROR: failed to send %u bytes of encrypted_secret2\n", encrypted_secret2_size);
        goto cleanup;
    }

cleanup:

    if (sockfd >= 0) {
        close(sockfd);
    }

    if (encrypted_secret1 != NULL) {
        free(encrypted_secret1);
    }

    if (encrypted_secret2 != NULL) {
        free(encrypted_secret2);
    }

    return 0;

}
