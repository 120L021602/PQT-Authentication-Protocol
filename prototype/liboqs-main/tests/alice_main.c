// 包含必要的库
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>
#include <time.h>
#include "read_socket.h"
#include "check_timestamp.h"

#define PORT 8080
#define BUFFER_SIZE 8000
#define MESSAGE_LEN 50

int main() 
{
    OQS_SIG *sig_a = NULL;
	uint8_t *pksa = NULL;
	uint8_t *sksa = NULL;
	uint8_t *message = NULL;
	uint8_t *signature = NULL;
	// size_t message_len = MESSAGE_LEN;
	size_t signature_len;
	OQS_STATUS rc;

    uint8_t *pksb = NULL;

    //alice生成dilithium_5的sig
    sig_a = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if(sig_a == NULL){
        printf("OQS_SIG_alg_dilithium_3 was not enabled at compile-time.\n");
        return OQS_ERROR;
    }

    // 为签名的公私钥和签名在堆上分配空间
    pksa = malloc(sig_a->length_public_key);
    sksa = malloc(sig_a->length_secret_key);
    // message = malloc(message_len);
    signature = malloc(sig_a->length_signature);
    if((pksa == NULL) || (sksa == NULL) || (signature == NULL)){
        fprintf(stderr, "ERROR: malloc(Alice) failed!\n");
        return OQS_ERROR;
    }

    // 为pksb分配空间
    pksb = malloc(sig_a->length_public_key);
    if(pksb == NULL){
        fprintf(stderr, "ERROR: malloc of pksb(Alice) failed!\n");
        return OQS_ERROR;
    }

    // 生成签名的公私钥对
    rc = OQS_SIG_keypair(sig_a, pksa, sksa);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_keypair(Alice) failed!\n");
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
		fprintf(stderr, "ERROR: malloc(Alice) failed!\n");
		// cleanup_heap(skn, shared_secret, pkn,
		//              ciphertext, kem);
        
        return OQS_ERROR;
	}

    // 生成协商密钥对
	rc = OQS_KEM_keypair(kem, pkn, skn);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_keypair failed!\n");
		// cleanup_heap(skn, shared_secret, pkn,
		//              ciphertext, kem);

		return OQS_ERROR;
	}



    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];
    // char *message = "Hello from client";

    // 创建客户端套接字
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    // 设置服务器地址和端口
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // 将IP地址从字符串转换为网络地址
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    // 连接到服务器
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    // // 发送消息到服务器
    // send(sock, message, strlen(message), 0);
    // printf("Hello message sent\n");

    // // 从服务器接收响应
    // memset(buffer, 0, sizeof(buffer));
    // if (read(sock, buffer, BUFFER_SIZE) < 0) {
    //     printf("\nRead failed \n");
    //     return -1;
    // }
    // printf("Server: %s\n", buffer);

    // 接收bob的签名公钥pksb
    // memset(buffer, 0, sizeof(buffer));
    if(!ReadSocket(sock, pksb, sig_a->length_public_key)){
        fprintf(stderr, "Alice failed to receive pksb.\n");
        return -1;
    }

    printf("Alice successfully received pksb!\n");

    // pksb = (uint8_t *)buffer;


    // 向bob发送签名公钥pksa
    printf("Alice sends pksa to Bob.\n");

    send(sock, pksa, sig_a->length_public_key, 0);

    // pkn||timestamp
    char *pkn_timestamp = NULL;
    pkn_timestamp = malloc(kem->length_public_key + sizeof(uint64_t));
    if(pkn_timestamp == NULL){
        fprintf(stderr, "ERROR: malloc of pkn_timestamp(Alice) failed!\n");
        return -1;
    }

    // 获取当前时间的 UNIX 时间戳
    time_t currentTime = time(NULL);

    // 将 time_t 类型的时间戳转换为 uint64_t 类型
    uint64_t timestamp_1 = (uint64_t)currentTime;

    // 测试
    // printf("第一次打印timestamp_1\n");
    // printf("%lx\n", timestamp_1);


    // 复制pkn到pkn_timestamp的前面
    for(int i = 0; i < kem->length_public_key; i ++){
        pkn_timestamp[i] = pkn[i];
    }

    // 复制timestamp_1到pkn_timestamp后面
    *((uint64_t *)(pkn_timestamp + kem->length_public_key)) = timestamp_1;

    // 测试
    // printf("打印拼接后的时间戳，看是否和第一次打印的timestamp_1相同\n");
    // for(int i = 0; i < 8; i ++){
    //     fprintf(stderr, "%02hhX", pkn_timestamp[kem->length_public_key + i]);
    //     // fprintf(stderr, "scuizi");
    // }

    // 此时pkn_timestamp已经是pkn和timestamp_1拼接的结果了

    // 用sksa将pkn_timestamp签名
    rc = OQS_SIG_sign(sig_a, signature, &sig_a->length_signature, pkn_timestamp, 
    kem->length_public_key + sizeof(uint64_t), sksa);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: Signature of pkn and timestamp(Alice) generating failed!\n");
		// cleanup_heap(pkn, skn, pkn_timestamp, signature, sig_a);
		return OQS_ERROR;
	}

    // 为signed_message_1分配空间
    char *signed_message_1 = NULL;
    size_t length_signed_message_1 = sig_a->length_signature + kem->length_public_key + sizeof(uint64_t);
    signed_message_1 = malloc(length_signed_message_1);
    if(signed_message_1 == NULL){
        fprintf(stderr, "ERROR: malloc of signed_message_1(Alice) failed!\n");
        return -1;
    }

    // fprintf(stderr, "1");
    // 将签名复制到signed_message_1的最前面
    for(int i = 0; i < sig_a->length_signature; i ++){
        signed_message_1[i] = signature[i];
    }

    // fprintf(stderr, "2");
    // 将pkn_timestamp复制到signed_message_1的后半部分
    for(int i = 0; i < kem->length_public_key + sizeof(uint64_t); i ++){
        signed_message_1[sig_a->length_signature + i] = pkn_timestamp[i];
    }

    // fprintf(stderr, "这个for没问题\n");
    // 此时signed_message_1已经是pkn_timestamp的签名和pkn_timestamp拼接的结果了

    // 向bob发送signed_message_1
    printf("Alice sends signed_message_1 to Bob.\n");

    send(sock, signed_message_1, length_signed_message_1, 0);

    // fprintf(stderr, "难道是这里有问题？\n");
    // 用receive_signed_message_2变量接收signed_message_2
    char *receive_signed_message_2 = NULL;
    receive_signed_message_2 = malloc(sig_a->length_signature + kem->length_ciphertext + sizeof(uint64_t));
    if(receive_signed_message_2 == NULL){
        fprintf(stderr, "ERROR: malloc of receive_signed_message_2(Alice) failed!\n");
        return OQS_ERROR;
    }


    // fprintf(stderr, "这里有问题？\n");
    // 接收signed_message_2
    // memset(buffer, 0, sizeof(buffer));
    if(!ReadSocket(sock, receive_signed_message_2, sig_a->length_signature + kem->length_ciphertext + sizeof(uint64_t))){
        fprintf(stderr, "Alice failed to receive signed_message_2.\n");
        return -1;
    }

    printf("Alice successfully received signed_message_2!\n");
    // fprintf(stderr, "这里不可能有问题？\n");
    // receive_signed_message_2 = buffer;

    // 获取ciphertext和时间戳
    char *receive_ciphertext_timestamp = NULL;
    receive_ciphertext_timestamp = malloc(kem->length_ciphertext + sizeof(uint64_t));
    if(receive_ciphertext_timestamp == NULL){
        fprintf(stderr, "ERROR: malloc of receive_ciphertext_timestamp(Alice) failed!\n");
        return -1;
    }

    // fprintf(stderr, "这里有木有问题？\n");

    // fprintf(stderr, "3");
    //用变量receive_ciphertext_timestamp接收ciphertext_timestamp
    for(int i = 0; i < kem->length_ciphertext + sizeof(uint64_t); i ++){
        receive_ciphertext_timestamp[i] = receive_signed_message_2[sig_a->length_signature + i];
    }

    // 用变量receive_signature_2接收Bob的signature
    uint8_t *receive_signature_2 = NULL;
    receive_signature_2 = malloc(sig_a->length_signature);
    if(receive_signature_2 == NULL){
        fprintf(stderr, "ERROR: malloc of receive_signature_2(Alice) failed!\n");
        return -1;
    }

    // fprintf(stderr, "4");
    for(int i = 0; i < sig_a->length_signature; i ++){
        receive_signature_2[i] = (uint8_t)receive_signed_message_2[i];
    }

    // 用pksb验签
    rc = OQS_SIG_verify(sig_a, receive_ciphertext_timestamp, kem->length_ciphertext + sizeof(uint64_t), 
    receive_signature_2, sig_a->length_signature, pksb);
    if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_verify(pksb) failed!\n");
		return OQS_ERROR;
	}

    printf("Signature of signed_message_2 is successfully verified!\n");

    // 若验签成功，则检查时间戳
    uint64_t receive_timestamp_2;
    receive_timestamp_2 = *(uint64_t *)(receive_ciphertext_timestamp + kem->length_ciphertext);
    if(!CheckTimestamp(receive_timestamp_2)){
        fprintf(stderr, "ERROR: timestamp of Bob verify failed!\n");
		return OQS_ERROR;
    }

    // 时间戳通过检验
    printf("Timestamp of signed_message_2 is successfully verified!\n");

    // fprintf(stderr, "5");
    // 获取ciphertext
    for(int i = 0; i < kem->length_ciphertext; i ++){
        ciphertext[i] = (uint8_t)receive_ciphertext_timestamp[i];
    }

    // 输入skn和ciphertext，得到共享密钥shared_secret
    rc = OQS_KEM_decaps(kem, shared_secret, ciphertext, skn);
    if(rc != OQS_SUCCESS){
        fprintf(stderr, "ERROR: Shared_secret of Alice generating failed!\n");
        return OQS_ERROR;
    }

    // Alice成功获得共享密钥shared_secret并将它打印出来
    printf("Alice successfully generates shared_secrect.\n");

    // fprintf(stderr, "6");

    printf("Alice's shared_secret is"); 
    for(int i = 0; i < kem->length_shared_secret; i ++){
        printf("%02hhX", shared_secret[i]);
    }
    
    printf("\n");

    // 若程序运行至此，说明Alice和Bob已经完成了双向身份认证，并完成了共享密钥的协商
    printf("So far, Alice and Bob have completed the two-way identity authentication and the negotiation of the shared_secret, and the 'YYH Protocal' is completed!\n");

    //释放堆内存
    free(sig_a);
    free(pksa);
    free(sksa);
    free(message);
    free(signature);
    free(receive_ciphertext_timestamp);
    free(receive_signature_2);
    free(receive_signed_message_2);
    

    return 0;
}


void cleanup_stack(uint8_t *secret_key, size_t secret_key_len, uint8_t *shared_secret,
                   size_t shared_secret_len) {
	OQS_MEM_cleanse(secret_key, secret_key_len);
	OQS_MEM_cleanse(shared_secret, shared_secret_len);
}

void cleanup_heap(uint8_t *secret_key, uint8_t *shared_secret, uint8_t *public_key,
                  uint8_t *ciphertext, OQS_KEM *kem) {
	if (kem != NULL) {
		OQS_MEM_secure_free(secret_key, kem->length_secret_key);
		OQS_MEM_secure_free(shared_secret, kem->length_shared_secret);
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(ciphertext);
	OQS_KEM_free(kem);
}
