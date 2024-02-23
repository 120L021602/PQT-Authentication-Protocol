// 包含必要的库
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <oqs/oqs.h>
#include <time.h>
#include "read_socket.h"
#include "check_timestamp.h"

#define PORT 8080
#define BUFFER_SIZE 8000

int main() 
{
    OQS_SIG *sig_b = NULL;
	uint8_t *pksb = NULL;
	uint8_t *sksb = NULL;
	uint8_t *message = NULL;
	uint8_t *signature = NULL;
	// size_t message_len = MESSAGE_LEN;
	size_t signature_len;
	OQS_STATUS rc;

    uint8_t *pksa = NULL;


    // 生成dilithium_3的sig
    sig_b = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if(sig_b == NULL){
        printf("OQS_SIG_alg_dilithium_3 was not enabled at compile-time.\n");
        return OQS_ERROR;
    }

    // 为签名的公私钥和签名在堆上分配空间
    pksb = malloc(sig_b->length_public_key);
    sksb = malloc(sig_b->length_secret_key);
    // message = malloc(message_len);
    signature = malloc(sig_b->length_signature);
    if((pksb == NULL) || (sksb == NULL) || (signature == NULL)){
        fprintf(stderr, "ERROR: malloc(Bob) failed!\n");
        return OQS_ERROR;
    }

    // 为pksa分配空间
    pksa = malloc(sig_b->length_public_key);
    if(pksa == NULL){
        fprintf(stderr, "ERROR: malloc of pksa(Bob) failed!\n");
        return OQS_ERROR;
    }

    // 生成签名的公私钥对
    rc = OQS_SIG_keypair(sig_b, pksb, sksb);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_keypair(Bob) failed!\n");
		return OQS_ERROR;
	}

    // kyber
    OQS_KEM *kem = NULL;
	uint8_t *pkn = NULL;
	uint8_t *skn = NULL;
	uint8_t *ciphertext = NULL;
	uint8_t *shared_secret = NULL;

	kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
	if (kem == NULL) {
		printf("OQS_KEM_kyber_768 was not enabled at compile-time.\n");
		return OQS_SUCCESS;
	}

	pkn = malloc(kem->length_public_key);
	skn = malloc(kem->length_secret_key);
	ciphertext = malloc(kem->length_ciphertext);
	shared_secret = malloc(kem->length_shared_secret);
	if ((pkn == NULL) || (skn == NULL) || (ciphertext == NULL) ||
	        (shared_secret == NULL)) {
		fprintf(stderr, "ERROR: malloc(Bob) failed!\n");
		// cleanup_heap(skn, shared_secret, pkn,
		//              ciphertext, kem);

		return OQS_ERROR;
	}
    
    
    
    
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE];
    char *hello = "Hello from server";

    // 创建服务器套接字
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // 设置服务器地址和端口
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // 将套接字绑定到服务器地址和端口
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // 开始监听连接请求
    if (listen(server_fd, 1) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    // 接受客户端连接
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
        perror("accept failed");
        exit(EXIT_FAILURE);
    }

    // // 从客户端接收数据并发送响应
    // memset(buffer, 0, sizeof(buffer));
    // if (read(new_socket, buffer, BUFFER_SIZE) < 0) {
    //     perror("read failed");
    //     exit(EXIT_FAILURE);
    // }
    // printf("Client: %s\n", buffer);

    // send(new_socket, hello, strlen(hello), 0);
    // printf("Hello message sent\n");

    // 向alice发送签名公钥pksb
    printf("Bob sends pksa to Alice.\n");

    send(new_socket, pksb, sig_b->length_public_key, 0);
    
    // 接收alice的公钥pksa
    // memset(buffer, 0, sizeof(buffer));
    if(!ReadSocket(new_socket, pksa, sig_b->length_public_key)){
        fprintf(stderr, "Bob failed to receive pksa.\n");
        return -1;
    }

    printf("Bob successfully received pksa!\n");

    // pksa = (uint8_t *)buffer;

    //signed_message_1的长度
    size_t length_signed_message_1 = sig_b->length_signature + kem->length_public_key + sizeof(uint64_t);

    // 用receive_signed_message_1变量接收signed_message_1
    char *receive_signed_message_1 = NULL;
    receive_signed_message_1 = malloc(length_signed_message_1);
    if(receive_signed_message_1 == NULL){
        fprintf(stderr, "ERROR: malloc of receive_signed_message_1(Bob) failed!\n");
        return OQS_ERROR;
    }

    // 接收Alice发送的signed_message_1
    // memset(buffer, 0, sizeof(buffer));
    if(!ReadSocket(new_socket, receive_signed_message_1, length_signed_message_1)){
        fprintf(stderr, "bob failed to receive signed_message_1.\n");
        return -1;
    }

    printf("Bob successfully received signed_messasge_1!\n");

    // receive_signed_message_1 = buffer;

    
    //获取pkn和时间戳
    char *receive_pkn_timestamp = NULL;
    receive_pkn_timestamp = malloc(kem->length_public_key + sizeof(uint64_t));
    if(receive_pkn_timestamp == NULL){
        fprintf(stderr, "ERROR: malloc of receive_pkn_timestamp(Bob) failed!\n");
        return -1;
    }

    // 用变量receive_pkn_timestamp接收pkn_timestamp
    for(int i = 0; i < kem->length_public_key + sizeof(uint64_t); i ++){
        receive_pkn_timestamp[i] = receive_signed_message_1[sig_b->length_signature + i];
    }

    // 用变量receive_signature接收signature
    uint8_t *receive_signature = NULL;
    receive_signature = malloc(sig_b->length_signature);
    if(receive_signature == NULL){
        fprintf(stderr, "ERROR: malloc of receive_signature(Bob) failed!\n");
        return -1;
    }

    for(int i = 0; i < sig_b->length_signature; i ++){
        receive_signature[i] = (uint8_t)receive_signed_message_1[i];
    }

    // 用pksa验签
    rc = OQS_SIG_verify(sig_b, receive_pkn_timestamp, kem->length_public_key + sizeof(uint64_t), 
                        receive_signature, sig_b->length_signature, pksa);
    if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_verify(pksa) failed!\n");
		return OQS_ERROR;
	}

    printf("Signature of signed_message_1 is successfully verified!\n");

    //若验签成功，则检查时间戳
    uint64_t receive_timestamp;
    receive_timestamp = *(uint64_t *)(receive_pkn_timestamp + kem->length_public_key);
    if(!CheckTimestamp(receive_timestamp)){
        fprintf(stderr, "ERROR: timestamp of Alice verify failed!\n");
		return OQS_ERROR;
    }

    // 时间戳通过检验
    printf("Timestamp of signed_message_1 is successfully verified!\n");

    // fprintf(stderr, "1");
    // 获取kyber的协商公钥pkn
    for(int i = 0; i < kem->length_public_key; i ++){
        pkn[i] = (uint8_t)receive_pkn_timestamp[i];
    }

    // fprintf(stderr, "2");
    // 输入pkn,得到密文ciphertext和共享密钥shared_secret
    rc = OQS_KEM_encaps(kem, ciphertext, shared_secret, pkn);
    if(rc != OQS_SUCCESS){
        fprintf(stderr, "ERROR: ciphertext and shared_secret(Bob) generating failed!\n");
        return OQS_ERROR;
    }

    // 若执行到此，则Bob已经拥有pkn和shared_secret
    // 下一步，将ciphertext和时间戳拼接的签名消息发送给Alice

    // fprintf(stderr, "3");
    // 获取时间戳
    time_t timestamp_bob = time(NULL);
    uint64_t timestamp_bob_uint64 = (uint64_t)timestamp_bob;

    // fprintf(stderr, "4");

    // 将ciphertext和时间戳拼接起来
    char *ciphertext_timestamp = NULL;
    ciphertext_timestamp = malloc(kem->length_ciphertext + sizeof(uint64_t));
    if(ciphertext_timestamp == NULL){
        fprintf(stderr, "ERROR: malloc of ciphertext_timestamp failed!\n");
        return OQS_ERROR;
    }

    // fprintf(stderr, "5");
    // 复制ciphertext到ciphertext_timestamp的前面
    for(int i = 0; i < kem->length_ciphertext; i ++){
        ciphertext_timestamp[i] = ciphertext[i];
    }

    // 复制timestamp到ciphertext_timestamp的后面
    *((uint64_t *)(ciphertext_timestamp + kem->length_ciphertext)) = timestamp_bob_uint64;


    // 用sksb将ciphertext_timestamp签名
    rc = OQS_SIG_sign(sig_b, signature, &sig_b->length_signature, ciphertext_timestamp, 
    kem->length_ciphertext + sizeof(uint64_t), sksb);
    if(rc != OQS_SUCCESS){
        fprintf(stderr, "Signature of ciphertext_timestamp(Bob) generating failed!\n");
        return OQS_ERROR;
    }

    // fprintf(stderr, "6");
    // 生成signed_message_2
    // 为signed_message_2分配空间
    char *signed_message_2 = NULL;
    signed_message_2 = malloc(sig_b->length_signature + kem->length_ciphertext + sizeof(uint64_t));
    if(signed_message_2 == NULL){
        fprintf(stderr, "ERROR: malloc of signed_message_2(Bob) failed!\n");
        return -1;
    }
    // 将签名复制到signed_message_2的最前面
    for(int i = 0; i < sig_b->length_signature; i ++){
        signed_message_2[i] = signature[i];
    }

    // 将ciphertext_timestamp复制到signed_message_2的后半部分
    for(int i = 0; i < kem->length_ciphertext + sizeof(uint64_t); i ++){
        signed_message_2[sig_b->length_signature + i] = ciphertext_timestamp[i];
    }

    // fprintf(stderr, "7");
    // 向alice发送signed_message_2
    printf("Bob sends signed_message_2 to Alice.\n");

    send(new_socket, signed_message_2, sig_b->length_signature + kem->length_ciphertext + sizeof(uint64_t), 0);

    // 至此，协议中bob的部分已经运行完毕

    // fprintf(stderr, "8");
    // 将shared_secret打印出来
    printf("Bob's shared_secret is:");
    for(int i = 0; i < kem->length_shared_secret; i ++){
        printf("%02hhX", shared_secret[i]);
    }

    printf("\n");

    // 释放堆内存
    free(sig_b);
    free(pksb);
    free(sksb);
    free(message);
    free(signature);
    free(receive_pkn_timestamp);
    free(receive_signature);

    return 0;
}


void cleanup_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len) {
	OQS_MEM_cleanse(secret_key, secret_key_len);
	OQS_MEM_cleanse(shared_secret_e, shared_secret_len);
	OQS_MEM_cleanse(shared_secret_d, shared_secret_len);
}

void cleanup_heap(uint8_t *secret_key, uint8_t *shared_secret_e,
                  uint8_t *shared_secret_d, uint8_t *public_key,
                  uint8_t *ciphertext, OQS_KEM *kem) {
	if (kem != NULL) {
		OQS_MEM_secure_free(secret_key, kem->length_secret_key);
		OQS_MEM_secure_free(shared_secret_e, kem->length_shared_secret);
		OQS_MEM_secure_free(shared_secret_d, kem->length_shared_secret);
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(ciphertext);
	OQS_KEM_free(kem);
}
