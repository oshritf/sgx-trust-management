/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

// This sample is confined to the communication between a SGX client platform
// and an ISV Application Server. 



#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>

#include "sgx_eid.h"
#include "sgx_urts.h"

#include "truce_u.h"

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
    int ret = 0;

    sgx_enclave_id_t enclave_id = 0;

    sgx_status_t status = SGX_SUCCESS;

    FILE* OUTPUT = stdout;

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
        fprintf(OUTPUT, "\nError: Failed to create enclave.");
        return ret;
    }
    else {
        fprintf(OUTPUT, "\nSuccessfully created SGX enclave.\n");
    }
    truce_config_t t_config;
    t_config.truce_server_address = sp_address;

    truce_session_t t_session;
    ret = truce_session(enclave_id, t_config, &t_session);
    if (0 != ret) {
        fprintf(OUTPUT, "\nError: Failed to create truce_session.");
        return ret;
    }
    else {
        fprintf(OUTPUT, "\nSuccessfully created truce_session.");
    }

 
    printf("\nEnter a character before exit ...\n");
    getchar();

    sgx_destroy_enclave(enclave_id);

    return ret;
}

