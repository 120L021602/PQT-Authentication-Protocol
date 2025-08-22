// #include "socket_zmq.h"
// #include <stdbool.h>
// #include <string.h>
// #include <tee_client_api.h>
#ifndef SOCKET_HANDLE_H
#define SOCKET_HANDLE_H

#include "cafun.h"

//void node_receive_server_handler(TEEC_Context ctx, TEEC_Session sess, char* send_buffer, int send_buffer_len, Sm9_Key* sm9_key, Sm9_Para* sm9_str, ca_oppo* oparams);
//void center_server_receive_handler(TEEC_Context ctx, TEEC_Session sess, char* send_buffer, int send_bufferLen, ca_self* ccParams);
void node_server_receive_handler(TEEC_Context ctx, TEEC_Session sess, TEEC_Context ctx2, TEEC_Session sess2, char* node_server_rec_buffer, char* send_buffer, int send_bufferLen, ca_oppo* oparams, ca_self* sparams, Sm9_Para* sm9_para, Sm9_Key* sm9_key);
//void center_server_receive_handler(uint8_t* ppube, char* center_rec_buffer, TEEC_Context ctx, TEEC_Session sess, char* send_buffer, int send_bufferLen, center_ca_params* ccParams);
void node_client_send_handler(int a, char* send_buffer, Sm9_Key* sm9_key, ca_self* self, uint8_t* sk_flag);
void node_client_receive_handler(char* node_client_rec_buffer, TEEC_Context ctx, TEEC_Session sess, Sm9_Key* sm9_key, ca_self* self, ca_oppo* oppo, Sm9_Para* sm9_para);
void pqc_node_client_send_handler(int a, char *send_buffer);
#endif