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

#include <openssl/rsa.h>

FILE* OUTPUT = stdout;

#include "truce_client.h"


int truce_client_get_enclave_record(const char* truce_server_address, uint8_t *truce_enc_id, int tid_len, truce_enclave_t *t_rec) 
{

    // Create connection to TruCE server

    int sockfd = 0, n = 0;
    struct sockaddr_in truce_srv_ip_addr; 

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return -1;
    } 

    memset(&truce_srv_ip_addr, '0', sizeof(truce_srv_ip_addr)); 

    truce_srv_ip_addr.sin_family = AF_INET;
    truce_srv_ip_addr.sin_port = htons(4000); // TODO

    if(inet_pton(AF_INET, truce_server_address, &truce_srv_ip_addr.sin_addr)<=0) //TODO
    {
        printf("\n inet_pton error occured\n");
        return -1;
    } 

    if( connect(sockfd, (struct sockaddr *)&truce_srv_ip_addr, sizeof(truce_srv_ip_addr)) < 0)
    {
       printf("\n Error : Connect Failed \n");
       return -1;
    } 
    fprintf(OUTPUT, "Connected to TruCE server\n");


    int tmp_int = htonl(tid_len);
    write(sockfd, &tmp_int, 4);
    write(sockfd, truce_enc_id, tid_len);



    n = read(sockfd, &tmp_int, 4);
    if (n != 4) {
        fprintf(stdout, "\nError missing bytes %d\n", n);
        close(sockfd);
        return -1;
    }

    int result = ntohl(tmp_int);

    if (result < 0) {
        fprintf(stdout, "\nNo enclave found %d\n", n);
        close(sockfd);
        return -1;
    }

    // Get enclave pub key
    n = read(sockfd, &tmp_int, 4);
    if (n != 4) {
        fprintf(stdout, "\nError missing bytes %d\n", n);
        close(sockfd);
        return -1;
    }
    int len = ntohl(tmp_int);
    t_rec->public_key = (uint8_t *)malloc(len+1);
    if (!t_rec->public_key)
    {
        fprintf(OUTPUT, "\nMemory error!\n");
        close(sockfd);
        return -1;
    }
    int left = len;
    while (left > 0) {
        n = read(sockfd, t_rec->public_key + (len - left), left);
        left -= n;
    }
    fprintf(stdout, "Received enclave public key, length: %d\n", len);
    t_rec->public_key_len = len;

    // Get MR_ENCLAVE & MR_SIGNER
    n = read(sockfd, &tmp_int, 4);
    if (n != 4) {
        fprintf(stdout, "\nError missing bytes %d\n", n);
        close(sockfd);
        return -1;
    }
    len = ntohl(tmp_int);
    t_rec->mr_enclave = (uint8_t *)malloc(len+1);
    t_rec->mr_signer = (uint8_t *)malloc(len+1);
    if (!t_rec->mr_enclave || !t_rec->mr_signer)
    {
        fprintf(OUTPUT, "\nMemory error!\n");
        close(sockfd);
        return -1;
    }
    left = len;
    while (left > 0) {
        n = read(sockfd, t_rec->mr_enclave + (len - left), left);
        left -= n;
    }
    left = len;
    while (left > 0) {
        n = read(sockfd, t_rec->mr_signer + (len - left), left);
        left -= n;
    }
    fprintf(stdout, "Received measurements of enclave & signer, length: %d\n", len);
    t_rec->mr_len = len;
    
    close(sockfd);
    return 0;
}

int truce_client_get_mr_length(truce_enclave_t t_rec) 
{
    return t_rec.mr_len;
}

int truce_client_extract_mr_enclave(truce_enclave_t t_rec, uint8_t *mr_enc) 
{
    memcpy(mr_enc, t_rec.mr_enclave, t_rec.mr_len);

    return 0;
}

int truce_client_extract_mr_signer(truce_enclave_t t_rec, uint8_t *mr_sig) 
{
    memcpy(mr_sig, t_rec.mr_signer, t_rec.mr_len);

    return 0;
}

int truce_client_get_pubkey_length(truce_enclave_t t_rec) 
{
    return t_rec.public_key_len;
}

int truce_client_extract_pubkey(truce_enclave_t t_rec, uint8_t *pubkey) 
{
    memcpy(pubkey, t_rec.public_key, t_rec.public_key_len);

    return 0;
}

int truce_client_encrypt_secret(truce_enclave_t t_enc, unsigned char *s_buf, uint8_t *secret, int secret_len)
{
    int pklen = truce_client_get_pubkey_length(t_enc);

    if (NULL == t_enc.pubkey_rsa) {
        uint8_t *pk = (uint8_t *)malloc(pklen);
        int ret = truce_client_extract_pubkey(t_enc, pk);
        t_enc.pubkey_rsa = d2i_RSAPublicKey(0, (const unsigned char**)&pk, pklen);
    }

    int s_len = RSA_public_encrypt(secret_len, secret, s_buf, t_enc.pubkey_rsa,
                                 RSA_PKCS1_PADDING);

    fprintf(OUTPUT, "Secret encrypted with enclave pub key. Len: %d\n", s_len);

    return s_len;
}

