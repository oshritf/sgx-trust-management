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



#include <stdint.h>
//#include <stdlib.h>
//#include <stdio.h>

#include "network_ra.h"
#include "service_provider.h"





// Used to send requests to the service provider sample.  It
// simulates network communication between the ISV app and the
// ISV service provider.  This would be modified in a real
// product to use the proper IP communication.
//
// @param server_url String name of the server URL
// @param p_req Pointer to the message to be sent.
// @param p_resp Pointer to a pointer of the response message.

// @return int

int ra_network_send_receive(const char *server_url,
    const ra_samp_request_header_t *p_req,
    ra_samp_response_header_t **p_resp)
{

    int ret = 0;

    int snd_buf_len = 8+p_req->size;
    uint8_t* snd_buf = (uint8_t *)malloc(snd_buf_len);
    memcpy(snd_buf, &p_req->type, 1);
    memcpy(snd_buf+1,&p_req->size, 4);
    memcpy(snd_buf+5,&p_req->align, 3);
    memcpy(snd_buf+8,&p_req->body, p_req->size);


    int get_response = 1;
    if (TYPE_RA_MSG0 == p_req->type) get_response = 0;


    int sockfd = 0, n = 0;
    struct sockaddr_in serv_addr; 


    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return 1;
    } 

    memset(&serv_addr, '0', sizeof(serv_addr)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(5000); 

    if(inet_pton(AF_INET, server_url, &serv_addr.sin_addr)<=0)
    {
        printf("\n inet_pton error occured\n");
        return 1;
    } 

    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
       printf("\n Error : Connect Failed \n");
       return 1;
    } 

    int tmp_int = htonl(snd_buf_len);
    write(sockfd, &tmp_int, sizeof(snd_buf_len));
    write(sockfd, snd_buf, snd_buf_len); 
    free(snd_buf);

    if (get_response) 
    {
        int rec_buf_len;
        n = read(sockfd, &rec_buf_len, 4);
        if (n != 4) fprintf(stdout, "\nError missing bytes %d\n", n);

        //fprintf(stdout, "Received message, length: %d\n", rec_buf_len);
        uint8_t* rec_buf = (uint8_t *)malloc(rec_buf_len);

        int left = rec_buf_len;
        while (left > 0) {
            n = read(sockfd, rec_buf, rec_buf_len);
            left -= n;
        }

        uint8_t type = *rec_buf;
        uint32_t size = *(uint32_t *)(rec_buf+3);
        //fprintf(stdout, "Message type: %d, body size: %d\n", type, size);

        *p_resp = (ra_samp_response_header_t*)malloc(
                       sizeof(ra_samp_response_header_t) + size);

        if(NULL == *p_resp)
        {
            fprintf(stdout, "\nError : failed to malloc");
        }
        (*p_resp)->type = type;
        (*p_resp)->size = size;
        memcpy((*p_resp)->status, (rec_buf+1), 2);
        memcpy((*p_resp)->align, (rec_buf+7), 1);
        memcpy((*p_resp)->body, (rec_buf+8), size);
        
        free(rec_buf);
    }
    
    close(sockfd);


    return ret;
}

// Used to free the response messages.  In the sample code, the
// response messages are allocated by the SP code.
//
//
// @param resp Pointer to the response buffer to be freed.

void ra_free_network_response_buffer(ra_samp_response_header_t *resp)
{
    if(resp!=NULL)
    {
        free(resp);
    }
}
