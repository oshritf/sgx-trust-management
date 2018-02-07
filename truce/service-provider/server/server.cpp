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
#include <limits.h>
#include <unistd.h>

#include<pthread.h>

#include "remote_attestation_result.h"
#include "network_ra.h"
#include "service_provider.h"

#include "sample_libcrypto.h"


pthread_t tid[2];

struct enclave_instance
{
    uint8_t *truce_id;
    uint32_t truce_id_len;
    uint8_t *public_key;
    uint32_t public_key_len;
    uint8_t *mr_enclave;
    uint8_t *mr_signer;
    uint32_t mr_len;
    struct enclave_instance *next;
};

struct enclave_instance *ei_list_head = NULL;
struct enclave_instance *ei_list_tail = NULL;

struct enclave_instance* find_enclave_instance(uint8_t *ereq_buf, int ereq_len)
{
    struct enclave_instance *ei = ei_list_head;

    while (ei != NULL) {
        if (ei->truce_id_len == ereq_len) {
            int match = 1;
            for (int i=0; i < ereq_len; i++) {
                if (ei->truce_id[i] != ereq_buf[i]) match = 0;
            }
            if (1 == match) return ei;
        }
        ei = ei->next;
    }

    return NULL;
} 

uint8_t *Mr_Enclave;
uint8_t *Mr_Signer;



void* certificate_service(void *arg) 
{

    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr;

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(4000); 

    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)); 

    listen(listenfd, 10); 

    while(1)
    {
        fprintf(stdout, "CS: Waiting for incoming TCP connections\n");
        connfd = accept(listenfd, (struct sockaddr*)NULL, NULL); 

        int tmp_int, n;
        int left = 4;
        while (left > 0) {
            n = read(connfd, &tmp_int + (4-left), left);
            left -= n;
        }

        int ereq_len = ntohl(tmp_int);

        uint8_t* ereq_buf = (uint8_t *)malloc(ereq_len);

        left = ereq_len;
        while (left > 0) {
            n = read(connfd, ereq_buf + (ereq_len - left), left);
            left -= n;
        }

        fprintf(stdout, "CS: Received enclave request, length: %d\n", ereq_len);

        struct enclave_instance *enclave = find_enclave_instance(ereq_buf, ereq_len);

        free(ereq_buf);

        if (NULL == enclave) {
            tmp_int = htonl(-1);
            write(connfd, &tmp_int, 4);
        }
        else {
            tmp_int = htonl(1);
            write(connfd, &tmp_int, 4);
            tmp_int = htonl(enclave->public_key_len);
            write(connfd, &tmp_int, 4);
            write(connfd, enclave->public_key, enclave->public_key_len);
            tmp_int = htonl(enclave->mr_len);
            write(connfd, &tmp_int, 4);
            write(connfd, enclave->mr_enclave, enclave->mr_len);
            write(connfd, enclave->mr_signer, enclave->mr_len);
        }

        //sleep(1);
        close(connfd);
     }
}


void* attestation_service(void *arg) 
{

    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr;


    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(5000); 

    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)); 

    listen(listenfd, 10); 

    while(1)
    {
        fprintf(stdout, "AS: Waiting for incoming TCP connections\n");

        struct sockaddr_in addr;
       // connfd = accept(listenfd, (struct sockaddr*)&addr, NULL); 
        connfd = accept(listenfd, (struct sockaddr*)NULL, NULL); 
        socklen_t addr_size = sizeof(struct sockaddr_in);
        int res = getpeername(connfd, (struct sockaddr *)&addr, &addr_size);
        char enclave_ip_str[20];
        uint8_t *enclave_ip = (uint8_t *) &(addr.sin_addr.s_addr);
        int enclave_ip_len = sizeof(&addr.sin_addr.s_addr);
        strcpy(enclave_ip_str, inet_ntoa(addr.sin_addr));
 
        fprintf(stdout, "AS: Connection from %s\n", enclave_ip_str);

        //for (int i =0; i < enclave_ip_len; i++) {printf("%d ",enclave_ip[i]);}


        int n = 0;
        int ret = 0;
        ra_samp_response_header_t* p_resp_msg;

        int tmp_int;
        int left = 4;
        while (left > 0) {
            n = read(connfd, &tmp_int + (4-left), left);
            left -= n;
        }

        int rec_buf_len = ntohl(tmp_int);

        fprintf(stdout, "\nReceived message, length: %d\n", rec_buf_len);


        uint8_t* rec_buf = (uint8_t *)malloc(rec_buf_len);

        left = rec_buf_len;
        while (left > 0) {
            n = read(connfd, rec_buf + (rec_buf_len - left), left);
            left -= n;
        }

        uint8_t type = *rec_buf;
        uint32_t size = *(uint32_t *)(rec_buf+1);
        fprintf(stdout, "\nMessage type: %d, body size: %d\n", type, size);

        ra_samp_request_header_t* p_req = (ra_samp_request_header_t*)malloc(
                       sizeof(ra_samp_request_header_t) + size);

        if(NULL == p_req)
        {
            fprintf(stdout, "\nError : failed to malloc");
        }
        p_req->type = type;
        p_req->size = size;
        if(memcpy_s(p_req->align, 3, (rec_buf+5), 3))
        {
            fprintf(stdout, "\nError : failed to memcpy_s - align");
        }
        if(memcpy_s(p_req->body, size, (rec_buf+8), size))
        {
            fprintf(stdout, "\nError : failed to memcpy_s - body");
        }


        free(rec_buf);

        int send_response = 0;

        // Taken from Intel's RemoteAttestation sample example,
        // Copyright (C) 2011-2016 Intel Corporation. All rights reserved.

        switch(p_req->type)
        {

        case TYPE_RA_MSG0:
            ret = sp_ra_proc_msg0_req((const sample_ra_msg0_t*)((uint8_t*)p_req
                + sizeof(ra_samp_request_header_t)),
                p_req->size);
            if (0 != ret)
            {
                fprintf(stderr, "\nError, call sp_ra_proc_msg1_req fail [%s].",
                    __FUNCTION__);
            }
            break;

        case TYPE_RA_MSG1:
            ret = sp_ra_proc_msg1_req((const sample_ra_msg1_t*)((uint8_t*)p_req
                + sizeof(ra_samp_request_header_t)),
                p_req->size,
                &p_resp_msg);
            if(0 != ret)
            {
                fprintf(stderr, "\nError, call sp_ra_proc_msg1_req fail [%s].",
                    __FUNCTION__);
            }
            else
            {
                send_response = 1;
            }
            break;

        case TYPE_RA_MSG3:
            ret =sp_ra_proc_msg3_req((const sample_ra_msg3_t*)((uint8_t*)p_req +
                sizeof(ra_samp_request_header_t)),
                p_req->size,
                &p_resp_msg);
            if(0 != ret)
            {
                fprintf(stderr, "\nError, call sp_ra_proc_msg3_req fail [%s].",
                    __FUNCTION__);
            }
            else
            {
                send_response = 1;
            }
            break;
        case TYPE_ENCRYPTED_MSG:{
            uint8_t message[1000]; //TODO
            uint32_t msg_length;
            ret = sp_ra_proc_encrypted_message(p_req, message, &msg_length);

            struct enclave_instance *ptr = (struct enclave_instance*)malloc(sizeof(struct enclave_instance));
            ptr->truce_id_len = msg_length;
            ptr->truce_id = (uint8_t *) malloc (ptr->truce_id_len);
            //memcpy(ptr->truce_id,enclave_ip,enclave_ip_len);
            memcpy(ptr->truce_id, message, ptr->truce_id_len);

            ptr->public_key_len = msg_length;
            ptr->public_key = (uint8_t *) malloc (ptr->public_key_len); 
            memcpy(ptr->public_key, message, ptr->public_key_len);
            ptr->mr_len = sizeof(sample_measurement_t);
            ptr->mr_enclave = (uint8_t *) malloc (ptr->mr_len);
            memcpy(ptr->mr_enclave, Mr_Enclave, ptr->mr_len);
            ptr->mr_signer = (uint8_t *) malloc (ptr->mr_len);
            memcpy(ptr->mr_signer, Mr_Signer, ptr->mr_len);
            ptr->next = NULL;

            if (NULL == ei_list_head) {
                ei_list_head = ptr;
                ei_list_tail = ptr;
            }
            else {
                ei_list_tail->next = ptr;
                ei_list_tail = ptr;
            }


            p_resp_msg = (ra_samp_response_header_t*)malloc(enclave_ip_len
                      + sizeof(ra_samp_response_header_t));
            p_resp_msg->size = enclave_ip_len;
            memcpy_s(p_resp_msg->body, enclave_ip_len, enclave_ip, enclave_ip_len);

            send_response = 1;


            fprintf(stdout, "\nAS: New enclave instance, public key len: %d\n", ptr->public_key_len);
            fprintf(stdout, "Truce ID len: %d \n", ptr->truce_id_len);
            //for (int i=0; i < ptr->truce_id_len; i++) {fprintf(stdout, "%d.",ptr->truce_id[i]);}
            //fprintf(stdout, "\n");

            break;}
        default:
            ret = -1;
            fprintf(stderr, "\nError, unknown ra message type. Type = %d [%s].",
                p_req->type, __FUNCTION__);
            break;
        }

        free(p_req);

        if (send_response) 
        {
            int snd_buf_len = 8+p_resp_msg->size;
            uint8_t* snd_buf = (uint8_t *)malloc(snd_buf_len);
            memcpy(snd_buf, &p_resp_msg->type, 1);
            memcpy(snd_buf+1, &p_resp_msg->status, 2);
            memcpy(snd_buf+3,&p_resp_msg->size, 4);
            memcpy(snd_buf+7,&p_resp_msg->align, 1);
            memcpy(snd_buf+8,&p_resp_msg->body, p_resp_msg->size);

            write(connfd, &snd_buf_len, sizeof(snd_buf_len));
            write(connfd, snd_buf, snd_buf_len); 

            free(snd_buf);

        }

//TODO free p_resp, p_resp->body etc

//        sleep(1);
        close(connfd);
     }
}

int main(int argc, char* argv[])
{

    int err = pthread_create(&(tid[0]), NULL, &attestation_service, NULL);
    if (err != 0)
        printf("\ncan't create AS thread :[%s]", strerror(err));
    else
        printf("\n AS Thread created successfully\n");

    err = pthread_create(&(tid[1]), NULL, &certificate_service, NULL);
    if (err != 0)
        printf("\ncan't create CS thread :[%s]", strerror(err));
    else
        printf("\n CS Thread created successfully\n");


    while (true) {sleep(1000);}
}


