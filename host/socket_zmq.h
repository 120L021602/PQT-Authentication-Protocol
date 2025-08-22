//
// Created by xy on 3/2/22.
//
#ifndef SOCKET_ZMQ_H
#define SOCKET_ZMQ_H

#define ZMQ_SUCCESS         0
#define ERROR_SEND_ERROR    -1
#define ERROR_RECEIVE_ERROR -2
#define ERROR_CLIENT_ERROR  -3
#define ERROR_SERVER_ERROR  -4
#include <stdbool.h>
#include <string.h>
#include "socket_handle.h"
#include "zmq.h"

int zmq_Send(void *socket, char *send_buffer, int send_bufferLen);
int zmq_Receive(void *socket, char *rec_buffer);
int zmq_Client(char *ipset, char *send_buffer, int send_bufferLen, char *rec_buffer);
//int zmq_Server(char *ipset, TEEC_Context ctx, TEEC_Session sess, ca_oppo* oparams, ca_self* sparams, Sm9_Para* sm9_para, Sm9_Key* sm9_key);

int zmq_Server(char *ipset, TEEC_Context ctx, TEEC_Session sess, TEEC_Context ctx2, TEEC_Session sess2, ca_oppo* oparams, ca_self* sparams, Sm9_Para* sm9_para, Sm9_Key* sm9_key)
{
    void * pCtx = NULL;
    void * pSock = NULL;

    if((pCtx = zmq_ctx_new()) == NULL)
    {
        printf("Error: Socket MainServer zmq_ctx_new() wrong! \n");
        return ERROR_SERVER_ERROR;
    }

    // 一对一通信模式 Server REP, Client REQ
    if((pSock = zmq_socket(pCtx, ZMQ_REP)) == NULL)
    {
        printf("Error: Socket MainServer zmq_socket() wrong! \n");
        zmq_ctx_destroy(pCtx);
        return ERROR_SERVER_ERROR;
    }

    if(zmq_bind(pSock, ipset) < 0)
    {
        printf("Error: Socket MainServer zmq_bind() wrong! \n");
        zmq_close(pSock);
        zmq_ctx_destroy(pCtx);
        return ERROR_SERVER_ERROR;
    }

    int timeout = 20000;
    zmq_setsockopt (pSock, ZMQ_RCVTIMEO, &timeout, sizeof(timeout));
    zmq_setsockopt (pSock, ZMQ_SNDTIMEO, &timeout, sizeof(timeout));
    while( 1 )
    {   
        char rec_buffer[3296];
        char send_buffer[3296];
        int send_buffer_len = 3295;
        int rec_val = zmq_Receive(pSock, rec_buffer);
        if(rec_val == -2){
            continue;
        }
        node_server_receive_handler(ctx, sess, ctx2, sess2, rec_buffer, send_buffer, send_buffer_len, oparams, sparams, sm9_para, sm9_key);
        zmq_Send(pSock, send_buffer, send_buffer_len);
        // center_server_receive_handler(rec_buffer, ctx, sess, send_buffer, send_buffer_len, ccParams);
        // printf("\noppoID:\n");
        // format_print(oparams->oppoid, 8);
        // printf("\noppoRID:\n");
        // format_print(oparams->opporid, 8);
        // printf("\noppoR:\n");
        // format_print(oparams->oppoR, 64);
        // printf("\noppoS:\n");
        // format_print(oparams->oppoS, 32);
    }
    zmq_close(pSock);
    zmq_ctx_destroy(pCtx);
    return ZMQ_SUCCESS;
}

#endif