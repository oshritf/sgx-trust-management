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

#include "truce_u.h"

#include <stdio.h>
#include <limits.h>
#include <unistd.h>


// Needed for definition of remote attestation messages.
#include "remote_attestation_result.h"

#include "truce_enclave_u.h"

// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"

// Needed to get service provider's information, in your real project, you will
// need to talk to real server.
#include "network_ra.h"

// Needed to create enclave and do ecall.
#include "sgx_urts.h"

// Needed to query extended epid group id.
#include "sgx_uae_service.h"

#include "service_provider.h"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

// In addition to generating and sending messages, this application
// can use pre-generated messages to verify the generation of
// messages and the information flow.
#include "sample_messages.h"

#include <sys/socket.h>
//#include <sys/types.h>
#include <netinet/in.h>
//#include <netdb.h>
#include <arpa/inet.h> 

#include <dirent.h> 




// Some utility functions to output some of the data structures passed between
// the ISV app and the remote attestation service provider.
void PRINT_BYTE_ARRAY(
    FILE *file, void *mem, uint32_t len)
{
    if(!mem || !len)
    {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        fprintf(file, "0x%x, ", array[i]);
        if(i % 8 == 7) fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}


void PRINT_ATTESTATION_SERVICE_RESPONSE(
    FILE *file,
    ra_samp_response_header_t *response)
{
    if(!response)
    {
        fprintf(file, "\t\n( null )\n");
        return;
    }

    fprintf(file, "RESPONSE TYPE:   0x%x\n", response->type);
    fprintf(file, "RESPONSE STATUS: 0x%x 0x%x\n", response->status[0],
            response->status[1]);
    fprintf(file, "RESPONSE BODY SIZE: %u\n", response->size);

    if(response->type == TYPE_RA_MSG2)
    {
        sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)(response->body);

        /*fprintf(file, "MSG2 gb - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->g_b), sizeof(p_msg2_body->g_b));

        fprintf(file, "MSG2 spid - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->spid), sizeof(p_msg2_body->spid));

        fprintf(file, "MSG2 quote_type : %hx\n", p_msg2_body->quote_type);

        fprintf(file, "MSG2 kdf_id : %hx\n", p_msg2_body->kdf_id);

        fprintf(file, "MSG2 sign_gb_ga - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sign_gb_ga),
                         sizeof(p_msg2_body->sign_gb_ga));

        fprintf(file, "MSG2 mac - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->mac), sizeof(p_msg2_body->mac));

        fprintf(file, "MSG2 sig_rl - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sig_rl),
                         p_msg2_body->sig_rl_size);*/
    }
    else if(response->type == TYPE_RA_ATT_RESULT)
    {
        sample_ra_att_result_msg_t *p_att_result =
            (sample_ra_att_result_msg_t *)(response->body);
        /*fprintf(file, "ATTESTATION RESULT MSG platform_info_blob - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->platform_info_blob),
                         sizeof(p_att_result->platform_info_blob));

        fprintf(file, "ATTESTATION RESULT MSG mac - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->mac), sizeof(p_att_result->mac));

        fprintf(file, "ATTESTATION RESULT MSG secret.payload_tag - %u bytes\n",
                p_att_result->secret.payload_size);

        fprintf(file, "ATTESTATION RESULT MSG secret.payload - ");
        PRINT_BYTE_ARRAY(file, p_att_result->secret.payload,
                p_att_result->secret.payload_size);*/
    }
    else
    {
        fprintf(file, "\nERROR in printing out the response. "
                       "Response of type not supported %d\n", response->type);
    }
}

int truce_add_secret(truce_session_t t_session, uint8_t* secret_buf, uint32_t secret_buf_size)
{

    sgx_status_t status = SGX_SUCCESS;
    int ret = add_secret(t_session.enclave_id, &status, secret_buf, secret_buf_size);
           
    if (SGX_SUCCESS != status) {
        fprintf(stdout, "\nError: Failed to add secret, %d\n", ret);
        return -1;
    }
    else {
        return 0;
    }
}

/*
int truce_public_key_len(sgx_enclave_id_t enclave_id, uint32_t* pub_key_len)
{

    sgx_status_t status = SGX_SUCCESS;
    int ret = get_public_key_len(enclave_id, &status, pub_key_len);
           
    if (SGX_SUCCESS != status) {
        fprintf(stdout, "\nError: Failed to get public key length, %d\n", ret);
        return -1;
    }
    else {
        return 0;
    }
}

int truce_get_public_key(sgx_enclave_id_t enclave_id, uint8_t* pub_key) {

    sgx_status_t status = SGX_SUCCESS;
    int ret = get_public_key(enclave_id, &status, pub_key);
           
    if (SGX_SUCCESS != status) {
        fprintf(stdout, "\nError: Failed to get public key, %d\n", ret);
        return -1;
    }
    else {
        return 0;
    }

}
*/

// This sample code doesn't have any recovery/retry mechanisms for the remote
// attestation. Since the enclave can be lost due S3 transitions, apps
// susceptible to S3 transitions should have logic to restart attestation in
// these scenarios.
#define _T(x) x
int truce_session(sgx_enclave_id_t enclave_id, truce_config_t config, truce_session_t *truce_session)
{

    int ret = 0;
    sgx_status_t status = SGX_SUCCESS;
    FILE* OUTPUT = stdout;

    char *sp_address = config.truce_server_address;


    if (NULL != config.seal_path) {
        // check for sealed secret. If available, skip remote attestation
        char *seal_file_name = config.seal_path;
        uint8_t *seal_buf;
        int seal_buf_len;
        int id_len;
        uint8_t *id;

        FILE *seal_file = fopen(seal_file_name, "rb");
        if (!seal_file) {
            fprintf(OUTPUT, "\nWarning: failed to open seal file %s \n",seal_file_name);
            fprintf(OUTPUT, "Performing remote attestation\n");
            goto ATTESTATION;
        }

        fread(&id_len, 4, 1, seal_file);
        id = (uint8_t *)malloc(id_len);
        fread(id, id_len, 1, seal_file);

        fread(&seal_buf_len, 4, 1, seal_file);
        seal_buf=(uint8_t *)malloc(seal_buf_len);
        fread(seal_buf, seal_buf_len, 1, seal_file);

        fclose(seal_file);

        ret = unseal_enclave_key(enclave_id, &status, seal_buf, seal_buf_len);

        free(seal_buf);

        if (SGX_SUCCESS != status) {
            fprintf(OUTPUT, "\nWarning: Failed to unseal the enclave key. File: %s\n",seal_file_name);
            fprintf(OUTPUT, "Performing remote attestation\n");
            goto ATTESTATION;
        }

        truce_session->enclave_id = enclave_id;
        truce_session->truce_id_length = id_len;
        truce_session->truce_id = id;
 
        fprintf(OUTPUT, "Unsealed from %s: \n - Skipping remote attestation\n",seal_file_name);
        return 0;

/*
        DIR           *d;
        struct dirent *dir;
        d = opendir(config.seal_path);
        if (!d)  {
            fprintf(OUTPUT, "\n Warning: Seal folder %s doesnt exist\n",config.seal_path);
        }
        else {

            while ((dir = readdir(d)) != NULL) {
 
                if (!strcmp(dir->d_name,".")) continue;
                if (!strcmp(dir->d_name,"..")) continue;

                char seal_file_name[sizeof(config.seal_path) + sizeof(dir->d_name)+5];
                strcpy(seal_file_name, config.seal_path);
                strcat(seal_file_name, "/");
                strcat(seal_file_name, dir->d_name);

                FILE *seal_file;
                uint8_t *seal_buf;
                int seal_file_len;
                int id_len;
                uint8_t *id;

                seal_file = fopen(seal_file_name, "rb");
                if (!seal_file) {
                    fprintf(OUTPUT, "\nError: failed to open seal file %s \n",seal_file_name);
                    continue;
                }

                fread(&id_len, 4, 1, seal_file);
                id = (uint8_t *)malloc(id_len);
                fread(id, id_len, 1, seal_file);

                int seal_buf_len;

                fread(&seal_buf_len, 4, 1, seal_file);
                seal_buf=(uint8_t *)malloc(seal_buf_len);
                fread(seal_buf, seal_buf_len, 1, seal_file);

                fclose(seal_file);

                ret = unseal_enclave_key(enclave_id, &status, seal_buf, seal_buf_len);

                free(seal_buf);

                if (SGX_SUCCESS != status) {
                    fprintf(OUTPUT, "\nWarning: Failed to unseal the enclave key. File: %s\n",seal_file_name);
                    continue;
                }

                truce_session->enclave_id = enclave_id;
                truce_session->truce_id_length = id_len;
                truce_session->truce_id = id;
 
                fprintf(OUTPUT, "Unsealed from %s: \n - Skipping remote attestation\n",seal_file_name);
                closedir(d);
                return 0;
            }
        }

        closedir(d);
        fprintf(OUTPUT, "Warning: Didn't find suitable seal file. Performing remote attestation\n");
*/
    }


/*    int sockfd = 0, connfd = 0;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, '0', sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0; 

    bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)); 
    char enclave_ip[20];
    socklen_t addr_size = sizeof(struct sockaddr_in);
    int res = getsockname(sockfd, (struct sockaddr *)&addr, &addr_size);
    strcpy(enclave_ip, inet_ntoa(addr.sin_addr));
    uint16_t enclave_port = addr.sin_port;
*/

ATTESTATION:    

    ra_samp_request_header_t *p_msg0_full = NULL;
    ra_samp_response_header_t *p_msg0_resp_full = NULL;
    ra_samp_request_header_t *p_msg1_full = NULL;
    ra_samp_response_header_t *p_msg2_full = NULL;
    sgx_ra_msg3_t *p_msg3 = NULL;
    ra_samp_response_header_t* p_att_result_msg_full = NULL;
    ra_samp_request_header_t *p_encrypted_msg = NULL;
    ra_samp_response_header_t *enc_ip_msg = NULL;
    
    int enclave_lost_retry_time = 1;
    int busy_retry_time = 4;
    sgx_ra_context_t context = INT_MAX;
    ra_samp_request_header_t* p_msg3_full = NULL;


    // Preparation for remote attestation by configuring extended epid group id.
    {
        uint32_t extended_epid_group_id = 0;
        ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);
        if (SGX_SUCCESS != ret)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, call sgx_get_extended_epid_group_id fail [%s].\n",
                __FUNCTION__);
            return ret;
        }
        fprintf(OUTPUT, "Call sgx_get_extended_epid_group_id success.\n");

        p_msg0_full = (ra_samp_request_header_t*)
            malloc(sizeof(ra_samp_request_header_t)
            +sizeof(uint32_t));
        if (NULL == p_msg0_full)
        {
            ret = -1;
            goto CLEANUP;
        }
        p_msg0_full->type = TYPE_RA_MSG0;
        p_msg0_full->size = sizeof(uint32_t);

        *(uint32_t*)((uint8_t*)p_msg0_full + sizeof(ra_samp_request_header_t)) = extended_epid_group_id;
        {

            //fprintf(OUTPUT, "MSG0 body generated\n");

            //PRINT_BYTE_ARRAY(OUTPUT, p_msg0_full->body, p_msg0_full->size);

        }
        // The ISV application sends msg0 to the SP.
        // The ISV decides whether to support this extended epid group id.
        fprintf(OUTPUT, "Sending msg0 to remote attestation service provider.\n");

        ret = ra_network_send_receive(sp_address,
            p_msg0_full,
            &p_msg0_resp_full);
        if (ret != 0)
        {
            fprintf(OUTPUT, "\nError, ra_network_send_receive for msg0 failed \n"
                "[%s].", __FUNCTION__);
            goto CLEANUP;
        }
        //fprintf(OUTPUT, "Sent MSG0 to remote attestation service.\n");
    }
    // Remote attestation will be initiated the ISV server challenges the ISV
    // app or if the ISV app detects it doesn't have the credentials
    // (shared secret) from a previous attestation required for secure
    // communication with the server.
    {
 
        ret = enclave_init_ra(enclave_id,
                                  &status,
                                  false,
                                  &context);
        //Ideally, this check would be around the full attestation flow.
        //} while (SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);

        if(SGX_SUCCESS != ret || status)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, call enclave_init_ra fail [%s].\n",
                    __FUNCTION__);
            goto CLEANUP;
        }
        //fprintf(OUTPUT, "Call enclave_init_ra success.\n");

        // isv application call uke sgx_ra_get_msg1
        p_msg1_full = (ra_samp_request_header_t*)
                      malloc(sizeof(ra_samp_request_header_t)
                             + sizeof(sgx_ra_msg1_t));
        if(NULL == p_msg1_full)
        {
            ret = -1;
            goto CLEANUP;
        }
        p_msg1_full->type = TYPE_RA_MSG1;
        p_msg1_full->size = sizeof(sgx_ra_msg1_t);
        do
        {
            ret = sgx_ra_get_msg1(context, enclave_id, sgx_ra_get_ga,
                                  (sgx_ra_msg1_t*)((uint8_t*)p_msg1_full
                                  + sizeof(ra_samp_request_header_t)));
            sleep(1); // Wait 1s between retries
        } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
        if(SGX_SUCCESS != ret)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, call sgx_ra_get_msg1 fail [%s].\n",
                    __FUNCTION__);
            goto CLEANUP;
        }
        else
        {
            fprintf(OUTPUT, "Call sgx_ra_get_msg1 success.\n");

            //fprintf(OUTPUT, "MSG1 body generated\n");

            //PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);

        }


        // The ISV application sends msg1 to the SP to get msg2,
        // msg2 needs to be freed when no longer needed.
        // The ISV decides whether to use linkable or unlinkable signatures.
        //fprintf(OUTPUT, "Sending msg1 to remote attestation service provider."
          //              "Expecting msg2 back.\n");


        ret = ra_network_send_receive(sp_address,
                                      p_msg1_full,
                                      &p_msg2_full);

        if(ret != 0 || !p_msg2_full)
        {
            fprintf(OUTPUT, "\nError, ra_network_send_receive for msg1 failed "
                            "[%s].\n", __FUNCTION__);
 
            goto CLEANUP;
        }
        else
        {
            // Successfully sent msg1 and received a msg2 back.
            // Time now to check msg2.
            if(TYPE_RA_MSG2 != p_msg2_full->type)
            {

                fprintf(OUTPUT, "\nError, didn't get MSG2 in response to MSG1. "
                                "[%s].\n", __FUNCTION__);

                goto CLEANUP;
            }

            fprintf(OUTPUT, "Sent MSG1 to remote attestation service "
                            "provider. Received MSG2.\n");
            //PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full,
            //                 sizeof(ra_samp_response_header_t)
            //                 + p_msg2_full->size);

            //fprintf(OUTPUT, "Descriptive representation of MSG2:\n");
            //PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT, p_msg2_full);

        }

        sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)((uint8_t*)p_msg2_full
                                      + sizeof(ra_samp_response_header_t));


        uint32_t msg3_size = 0;
        
        {
            busy_retry_time = 2;
            // The ISV app now calls uKE sgx_ra_proc_msg2,
            // The ISV app is responsible for freeing the returned p_msg3!!
            do
            {
                ret = sgx_ra_proc_msg2(context,
                                   enclave_id,
                                   sgx_ra_proc_msg2_trusted,
                                   sgx_ra_get_msg3_trusted,
                                   p_msg2_body,
                                   p_msg2_full->size,
                                   &p_msg3,
                                   &msg3_size);
            } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
            if(!p_msg3)
            {
                fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2 fail. "
                                "p_msg3 = 0x%p [%s].\n", p_msg3, __FUNCTION__);
                ret = -1;
                goto CLEANUP;
            }
            if(SGX_SUCCESS != (sgx_status_t)ret)
            {
                fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2 fail. "
                                "ret = 0x%08x [%s].\n", ret, __FUNCTION__);
                ret = -1;
                goto CLEANUP;
            }
            else
            {
                fprintf(OUTPUT, "Call sgx_ra_proc_msg2 success.\n");
                //fprintf(OUTPUT, "Got MSG3 \n");
            }
        }

        //PRINT_BYTE_ARRAY(OUTPUT, p_msg3, msg3_size);

        uint8_t *mr_Enclave = (uint8_t *) malloc(sizeof(sample_measurement_t));
        uint8_t *mr_Signer = (uint8_t *) malloc(sizeof(sample_measurement_t));

        sample_quote_t *p_quote = (sample_quote_t *)p_msg3->quote;

        fprintf(OUTPUT, "mr_enclave: ");
        for(int i=0;i<sizeof(sample_measurement_t);i++)
        {

            fprintf(OUTPUT, "%02x",p_quote->report_body.mr_enclave[i]);
            mr_Enclave[i] = p_quote->report_body.mr_enclave[i];
        }
        fprintf(OUTPUT, "\nmr_signer: ");
        for(int i=0;i<sizeof(sample_measurement_t);i++)
        {

            fprintf(OUTPUT, "%02x",p_quote->report_body.mr_signer[i]);
            mr_Signer[i] = p_quote->report_body.mr_signer[i];
        }
        fprintf(OUTPUT, "\n");


        p_msg3_full = (ra_samp_request_header_t*)malloc(
                       sizeof(ra_samp_request_header_t) + msg3_size);
        if(NULL == p_msg3_full)
        {
            ret = -1;
            goto CLEANUP;
        }
        p_msg3_full->type = TYPE_RA_MSG3;
        p_msg3_full->size = msg3_size;
        memcpy(p_msg3_full->body, p_msg3, msg3_size);
        

        // The ISV application sends msg3 to the SP to get the attestation
        // result message, attestation result message needs to be freed when
        // no longer needed. The ISV service provider decides whether to use
        // linkable or unlinkable signatures. The format of the attestation
        // result is up to the service provider. This format is used for
        // demonstration.  Note that the attestation result message makes use
        // of both the MK for the MAC and the SK for the secret. These keys are
        // established from the SIGMA secure channel binding.
        ret = ra_network_send_receive(sp_address,
                                      p_msg3_full,
                                      &p_att_result_msg_full);
        if(ret || !p_att_result_msg_full)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, sending msg3 failed [%s].\n", __FUNCTION__);
            goto CLEANUP;
        }


        sample_ra_att_result_msg_t * p_att_result_msg_body =
            (sample_ra_att_result_msg_t *)((uint8_t*)p_att_result_msg_full
                                           + sizeof(ra_samp_response_header_t));
        if(TYPE_RA_ATT_RESULT != p_att_result_msg_full->type)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError. Sent MSG3 successfully, but the message "
                            "received was NOT of type att_msg_result. Type = "
                            "%d. [%s].\n", p_att_result_msg_full->type,
                             __FUNCTION__);
            goto CLEANUP;
        }
        else
        {
            fprintf(OUTPUT, "Sent MSG3 successfully. Received an attestation "
                            "result message back.\n");
        }

        //fprintf(OUTPUT, "\nATTESTATION RESULT RECEIVED - ");
        /*PRINT_BYTE_ARRAY(OUTPUT, p_att_result_msg_full->body,
                         p_att_result_msg_full->size);*/


        // Check the MAC using MK on the attestation result message.
        // The format of the attestation result message is ISV specific.
        // This is a simple form for demonstration. In a real product,
        // the ISV may want to communicate more information.
        ret = verify_att_result_mac(enclave_id,
                &status,
                context,
                (uint8_t*)&p_att_result_msg_body->platform_info_blob,
                sizeof(ias_platform_info_blob_t),
                (uint8_t*)&p_att_result_msg_body->mac,
                sizeof(sgx_mac_t));
        if((SGX_SUCCESS != ret) ||
           (SGX_SUCCESS != status))
        {
            ret = -1;
            fprintf(OUTPUT, "\nError: INTEGRITY FAILED - attestation result "
                            "message MK based cmac failed in [%s].",
                            __FUNCTION__);
            goto CLEANUP;
        }

        bool attestation_passed = true;
        // Check the attestation result for pass or fail.
        // Whether attestation passes or fails is a decision made by the ISV Server.
        // When the ISV server decides to trust the enclave, then it will return success.
        // When the ISV server decided to not trust the enclave, then it will return failure.
        if(0 != p_att_result_msg_full->status[0]
           || 0 != p_att_result_msg_full->status[1])
        {
            fprintf(OUTPUT, "\nError, attestation result message MK based cmac "
                            "failed in [%s].", __FUNCTION__);
            attestation_passed = false;
        }

        // The attestation result message should contain a field for the Platform
        // Info Blob (PIB).  The PIB is returned by attestation server in the attestation report.
        // It is not returned in all cases, but when it is, the ISV app
        // should pass it to the blob analysis API called sgx_report_attestation_status()
        // along with the trust decision from the ISV server.
        // The ISV application will take action based on the update_info.
        // returned in update_info by the API.  
        // This call is stubbed out for the sample.
        // 
        // sgx_update_info_bit_t update_info;
        // ret = sgx_report_attestation_status(
        //     &p_att_result_msg_body->platform_info_blob,
        //     attestation_passed ? 0 : 1, &update_info);


        
        fprintf(OUTPUT, "\nRemote attestation success!\n");


        fprintf(OUTPUT, "Generating new enclave keys\n");
        uint8_t enc_pub_key_buf[1000]; // TODO
        uint32_t enc_pub_key_buf_len;
        ret = generate_enclave_keys(enclave_id, &status, context, enc_pub_key_buf, 
                   &enc_pub_key_buf_len, p_att_result_msg_body->secret.payload_tag);

        //PRINT_BYTE_ARRAY(OUTPUT, pub_key_buf, pub_key_buf_len);


        //fprintf(OUTPUT, "Enclave port %d \n", enclave_port); 

        p_encrypted_msg = (ra_samp_request_header_t*)
            malloc(sizeof(ra_samp_request_header_t)
            +enc_pub_key_buf_len);
        if (NULL == p_encrypted_msg)
        {
            ret = -1;
            goto CLEANUP;
        }
        p_encrypted_msg->type = TYPE_ENCRYPTED_MSG;
        p_encrypted_msg->size = enc_pub_key_buf_len;
        //memcpy(p_encrypted_msg->body, &enclave_port, 2);
        memcpy(p_encrypted_msg->body, enc_pub_key_buf, enc_pub_key_buf_len);

        ret = ra_network_send_receive(sp_address,
            p_encrypted_msg, &enc_ip_msg);


        /*Truce_Id_Len = enc_ip_msg->size + 2;
        Truce_Id = (uint8_t *)malloc(Truce_Id_Len);
        memcpy(Truce_Id, enc_ip_msg->body, enc_ip_msg->size);
        memcpy(Truce_Id + enc_ip_msg->size, &enclave_port, 2);

        fprintf(OUTPUT, "Truce ID: ");
        for (int i=0; i < Truce_Id_Len; i++) {fprintf(OUTPUT, "%d.",Truce_Id[i]);}
        fprintf(OUTPUT, "\n");*/

        uint32_t pk_len;
        ret = get_public_key_len(enclave_id, &status, &pk_len);
        uint8_t pk[100];
        ret = get_public_key(enclave_id, &status, pk);


        truce_session->enclave_id = enclave_id;
        truce_session->truce_id_length = pk_len;
        truce_session->truce_id = (uint8_t *)malloc(pk_len);
        memcpy(truce_session->truce_id, pk, pk_len);

        fprintf(OUTPUT, "Truce ID len: %d \n",pk_len);
    }

CLEANUP:
    // Clean-up
    // Need to close the RA key state.
    if(INT_MAX != context)
    {
        int ret_save = ret;
        ret = enclave_ra_close(enclave_id, &status, context);
        if(SGX_SUCCESS != ret || status)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, call enclave_ra_close fail [%s].",
                    __FUNCTION__);
        }
        else
        {
            // enclave_ra_close was successful, let's restore the value that
            // led us to this point in the code.
            ret = ret_save;
        }
        //fprintf(OUTPUT, "Call enclave_ra_close success.\n");
    }


    ra_free_network_response_buffer(p_msg0_resp_full);
    ra_free_network_response_buffer(p_msg2_full);
    ra_free_network_response_buffer(p_att_result_msg_full);
    ra_free_network_response_buffer(enc_ip_msg);

    // p_msg3 is malloc'd by the untrusted KE library. App needs to free.
    SAFE_FREE(p_msg3);
    SAFE_FREE(p_msg3_full);
    SAFE_FREE(p_msg1_full);
    SAFE_FREE(p_msg0_full);
    SAFE_FREE(p_encrypted_msg);

    // Seal the enclave key
    if (NULL != config.seal_path) {
        /*char seal_file_name[sizeof(config.seal_path) + 20];
        strcpy(seal_file_name, config.seal_path);
        strcat(seal_file_name, "/seal_file");*/
        char *seal_file_name = config.seal_path;

        FILE *seal_file;
        uint8_t seal_buf[4000]; // TODO
        uint32_t seal_file_len;

        ret = seal_enclave_key(enclave_id, &status, seal_buf, &seal_file_len);
        if (SGX_SUCCESS != status) {
            fprintf(OUTPUT, "\nError: Failed to seal the enclave key\n");
        }
        else {
            seal_file = fopen(seal_file_name, "wb");
            if (!seal_file)
            {
                fprintf(OUTPUT, "\nError: Failed to open seal file for writing %s\n",seal_file_name);
            }
            else 
            {
                fwrite(&(truce_session->truce_id_length), 1, 4, seal_file);
                fwrite(truce_session->truce_id, 1, truce_session->truce_id_length, seal_file);
                fwrite(&seal_file_len, 1, 4, seal_file);
                fwrite(seal_buf, 1, seal_file_len, seal_file);
                fclose (seal_file);
                fprintf(OUTPUT, "Successfully sealed keys to file %s\n",seal_file_name);
            }
        }
    }

    return ret;
}


