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



#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>

#include "sgx_eid.h"
#include "sgx_urts.h"
#include "truce_u.h"
#include "defs.h"
#include "truce_enclave_u.h"


#define ENCLAVE_PATH "truce_enclave.signed.so"

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}


int main(int argc, char* argv[])
{
    sgx_status_t ret = SGX_SUCCESS;
    int listenfd = -1;
    int connfd = -1;
    sgx_enclave_id_t enclave_id = 0;

    sgx_status_t status = SGX_SUCCESS;

    FILE* OUTPUT = stdout;

    if (argc < 2) {
        printf("ERROR: Need IP address as argument\n");
        return 1;
    }
    char* sp_address = argv[1];

    int launch_token_update = 0;
    sgx_launch_token_t launch_token = {0};
    memset(&launch_token, 0, sizeof(sgx_launch_token_t));
    ret = sgx_create_enclave(ENCLAVE_PATH,
                                     SGX_DEBUG_FLAG,
                                     &launch_token,
                                     &launch_token_update,
                                     &enclave_id, NULL);
    if (SGX_SUCCESS != ret) {
        fprintf(OUTPUT, "ERROR: Failed to create enclave.");
        return ret;
    }
    fprintf(OUTPUT, "Successfully created SGX enclave.\n");

    truce_config_t t_config;
    t_config.truce_server_address = sp_address;
    if (argc >= 3) {
        t_config.seal_path = argv[2];
    }

    truce_session_t t_session;
    if (!truce_session(enclave_id, t_config, t_session)) {
        fprintf(OUTPUT, "ERROR: Failed to create truce_session.\n");
        return 1;
    }
    fprintf(OUTPUT, "Successfully created truce_session.\n");

    printf("Received t_id:\n");
    print_buffer((uint8_t *) &t_session.truce_id, sizeof(t_session.truce_id));

    // Creating a listening socket. Waiting for clients connections.
    if (!inet_listen(listenfd, 6000)) {
        fprintf(OUTPUT, "ERROR: Failed to listen on port %d.\n", 6000);
        return 1;
    }

    while (true) {
        if (!inet_accept(connfd, listenfd)) {
            fprintf(OUTPUT, "ERROR: inet_accept has failed.\n");
            return 1;
        }

        if (!write_all(connfd, t_session.truce_id, sizeof(t_session.truce_id))) {
            fprintf(OUTPUT, "ERROR: failed to write %lu bytes of truce_id.\n", sizeof(t_session.truce_id));
            return 1;
        }

        // Reading secrets
        while (true) {
            uint8_t *secret = NULL;
            uint32_t secret_size = 0;

            if (!read_all(connfd, (uint8_t *) &secret_size, 4)) {
                fprintf(OUTPUT, "Closing connection\n");
                close(connfd);
                break;
            }
            secret = (uint8_t *) malloc(secret_size);
            if (secret == NULL) {
                fprintf(OUTPUT, "ERROR: Failed to allocate %u bytes of secret\n", secret_size);
                close(connfd);
                return 1;
            }

            if (!read_all(connfd, (uint8_t *) secret, secret_size)) {
                fprintf(OUTPUT, "ERROR: Failed to receive %u bytes of secret\n", secret_size);
                close(connfd);
                free(secret);
                return 1;
            }

            ret = ECALL_add_secret(enclave_id, &status, secret, secret_size);
            if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
                fprintf(OUTPUT, "ERROR: ECALL_add_secret has failed\n");
                close(connfd);
                free(secret);
                return 1;
            }

            free(secret);
        }

    }

 
    /*printf("\nEnter a character before exit ...\n");
    getchar();*/

    sgx_destroy_enclave(enclave_id);

    return ret;
}

