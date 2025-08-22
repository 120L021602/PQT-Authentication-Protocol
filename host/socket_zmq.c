//
// Created by xy on 3/2/22.
//
#include "socket_zmq.h"

/*
 *  socket      对应通信socket
 *  send_buffer 待发送数据
 *  bufferLen   待发送数据长度
 */
int zmq_Send(void *socket, char *send_buffer, int send_bufferLen)
{
    int rc = zmq_send (socket, send_buffer, send_bufferLen + 1, 0);
    if(rc = send_bufferLen + 1)
    {
        return ZMQ_SUCCESS;
    } else {
        printf(" Error: Send Failed! \n");
        return ERROR_SEND_ERROR;
    }
}

/*
 *  socket      对应通信socket
 *  rec_buffer  存数据buffer，长度为3360
 */
int zmq_Receive(void *socket, char *rec_buffer)
{
    memset(rec_buffer, 0, 3360);

    int rc = zmq_recv (socket, rec_buffer, 3360, 0);
    if(rc > 0 && rc < 3360)
    {
        return ZMQ_SUCCESS;
    } else {
        printf(" Receive Waiting! \n");
        return ERROR_RECEIVE_ERROR;
    }
}

/*
 *  ipset       需要通信的Server对象ip，固定格式 "tcp://" + ip + ":" + port
 *  send_buffer 待发送数据
 *  bufferLen   待发送数据长度
 *  rec_buffer  存数据buffer，长度为1024
 */
int zmq_Client(char *ipset, char *send_buffer, int send_bufferLen, char *rec_buffer)
{
    void * pCtx = NULL;
    void * pSock = NULL;

    if((pCtx = zmq_ctx_new()) == NULL)
    {
        printf("Error: Socket MainServer zmq_ctx_new() wrong! \n");
        return ERROR_CLIENT_ERROR;
    }

    // 一对一通信模式 Server REP, Client REQ
    if((pSock = zmq_socket(pCtx, ZMQ_REQ)) == NULL)
    {
        printf("Error: Socket MainServer zmq_socket() wrong! \n");
        zmq_ctx_destroy(pCtx);
        return ERROR_CLIENT_ERROR;
    }

    if(zmq_connect(pSock, ipset) < 0)
    {
        printf("Error: Socket MainServer zmq_bind() wrong! \n");
        zmq_close(pSock);
        zmq_ctx_destroy(pCtx);
        return ERROR_CLIENT_ERROR;
    }

    // 设置超时机制
    int timeout = 20000;
    zmq_setsockopt (pSock, ZMQ_SNDTIMEO, &timeout, sizeof(timeout));
    zmq_setsockopt (pSock, ZMQ_RCVTIMEO, &timeout, sizeof(timeout));

    if(zmq_Send(pSock, send_buffer, send_bufferLen) != ZMQ_SUCCESS)
    {
        printf("\nsend error\n");
        return ERROR_SEND_ERROR;
    }

    if(zmq_Receive(pSock, rec_buffer) != ZMQ_SUCCESS)
    {
        printf("\nreceive error\n");
        return ERROR_RECEIVE_ERROR;
    }

    zmq_close(pSock);
    zmq_ctx_destroy(pCtx);
    return ZMQ_SUCCESS;
}

// int zmq_Server(char *ipset, TEEC_Context ctx, TEEC_Session sess, ca_oppo* oparams, ca_self* sparams, Sm9_Para* sm9_para, Sm9_Key* sm9_key)
// {
//     void * pCtx = NULL;
//     void * pSock = NULL;

//     if((pCtx = zmq_ctx_new()) == NULL)
//     {
//         printf("Error: Socket MainServer zmq_ctx_new() wrong! \n");
//         return ERROR_SERVER_ERROR;
//     }

//     // 一对一通信模式 Server REP, Client REQ
//     if((pSock = zmq_socket(pCtx, ZMQ_REP)) == NULL)
//     {
//         printf("Error: Socket MainServer zmq_socket() wrong! \n");
//         zmq_ctx_destroy(pCtx);
//         return ERROR_SERVER_ERROR;
//     }

//     if(zmq_bind(pSock, ipset) < 0)
//     {
//         printf("Error: Socket MainServer zmq_bind() wrong! \n");
//         zmq_close(pSock);
//         zmq_ctx_destroy(pCtx);
//         return ERROR_SERVER_ERROR;
//     }

//     int timeout = 5000;
//     zmq_setsockopt (pSock, ZMQ_RCVTIMEO, &timeout, sizeof(timeout));
//     zmq_setsockopt (pSock, ZMQ_SNDTIMEO, &timeout, sizeof(timeout));
//     while( 1 )
//     {   
//         char rec_buffer[1024];
//         char send_buffer[256];
//         int send_buffer_len = 256;
//         zmq_Receive(pSock, rec_buffer);
//         node_server_receive_handler(ctx, sess, send_buffer, send_buffer_len, oparams, sparams, sm9_para, sm9_key);

//         // center_server_receive_handler(rec_buffer, ctx, sess, send_buffer, send_buffer_len, ccParams);
//         printf("\n oppoID:\n");
//         for(int i=0;i<8;i++){
// 		printf("%02X ",oparams->oppoid);
//         }
//         printf("\n oppoRID:\n");
//         for(int i=0;i<8;i++){
//             printf("%02X ",oparams->opporid);
//         }
//         printf("\n oppoR:\n");
//         for(int i=0;i<64;i++){
//             printf("%02X ",oparams->oppoR);
//         }
//         printf("\n oppoS:\n");
//         for(int i=0;i<32;i++){
//             printf("%02X ",oparams->oppoS);
//         }
//         // printf("\n nodenkid:\n");
//         // for(int i=0;i<112;i++){
//         //     printf("%02X ",ccParams->enkid[i]);
//         // }
//         // printf("\n nodenpkey:\n");
//         // for(int i=0;i<128;i++){
//         //     printf("%02X ",ccParams->enpkey[i]);
//         // }
//         // zmq_Send(pSock, send_buffer, send_buffer_len);
        
//     }
//     zmq_close(pSock);
//     zmq_ctx_destroy(pCtx);
//     return ZMQ_SUCCESS;
// }