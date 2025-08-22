// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <stdio.h>
#include <talib1.h>
#include <bn_pairing.h>
#include <tee_internal_api.h>
#include "utility.h"
#include <libs_ta2.h>
#include "string.h"
//// SECURITY_DEFINES
#define TA_SECURE_STORAGE_UUID \
		{ 0xf4e750bb, 0x1437, 0x4fbf, \
			{ 0x87, 0x85, 0x8d, 0x35, 0x80, 0xc3, 0x49, 0x94 } }

#define TA_SECURE_STORAGE_CMD_READ_RAW		0
#define TA_SECURE_STORAGE_CMD_WRITE_RAW		1
#define TA_SECURE_STORAGE_CMD_DELETE		2

#define COUNTS 50
void secure_read(uint8_t* package_id, uint8_t *package_context)
{	
	printf("\nSk search start:");
	TEE_Result res;
	TEE_TASessionHandle sess;
	//printf("\nwrong1\n");
	TEE_UUID secure_storage_uuid = TA_SECURE_STORAGE_UUID;
	//printf("\nwrong2\n");
	uint32_t time = 10;
	uint32_t ret_origin;
	uint32_t param_types1;
	TEE_Param params1[4];
	//printf("\nwrong3\n");
	uint8_t *cur_id = package_id;
	param_types1 = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	params1[0].memref.buffer = cur_id;
	params1[0].memref.size = 8;
	params1[1].memref.buffer = package_context;
	params1[1].memref.size = 32;
	//printf("\nwrong4\n");
	res = TEE_OpenTASession(&secure_storage_uuid, time, param_types1, params1, &sess, &ret_origin);
	//printf("\nwrong5\n");
	if (res != TEE_SUCCESS)
		printf("TEE_Opensession failed with code 0x%x origin 0x%x",
			res, ret_origin);
	//printf("\nwrong6\n");
	res = TEE_InvokeTACommand(sess, time, TA_SECURE_STORAGE_CMD_READ_RAW, param_types1, params1, &ret_origin);
	if (res != TEE_SUCCESS){
		printf("\nSk search defeat!\n");
		printf( "TEE_Invokecommand failed with code 0x%x origin 0x%x",
			res, ret_origin);
	}
	printf("\nsearch_id:\n");
	format_print(cur_id, 8);
	printf("\nread_package:\n");
	format_print(package_context, 32);
	printf("\nSk search successful!\n");
	TEE_CloseTASession(sess);
}


void secure_delete(uint8_t* delete_id)
{
	TEE_Result res1;
	TEE_TASessionHandle sess;
	TEE_UUID uuid = TA_SECURE_STORAGE_UUID;
	uint32_t time=10;
	uint32_t ret_origin;
	uint32_t param_types1;
	TEE_Param params1[4];
	param_types1 = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	params1[0].memref.buffer = delete_id;
	params1[0].memref.size = 8;
	res1 = TEE_OpenTASession(&uuid, time, param_types1, params1, &sess, &ret_origin);
	if (res1 != TEE_SUCCESS)
		printf("TEE_Opensession failed with code 0x%x origin 0x%x",
			res1, ret_origin);
	//printf("\nwrong6\n");
	res1 = TEE_InvokeTACommand(sess,time, TA_SECURE_STORAGE_CMD_DELETE, param_types1,params1,&ret_origin);
	if (res1 != TEE_SUCCESS)
		printf( "TEE_Invokecommand failed with code 0x%x origin 0x%x",
			res1, ret_origin);
	printf("\nKey deleted successful!\n");
}

TEE_Result TA_CreateEntryPoint(void)
{
	printf("TA2_CreateEntryPoint()\n");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	printf("TA2_DestroyEntryPoint()\n");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
		TEE_Param __unused params[4],
		void __unused **sess_ctx)
{
	//结构体初始化
	otp_cons_init(otp_cons, 5);
	otp_c = NULL;
	server_otp_c = NULL;
	temp_msg_c = NULL;
	uint8_t first_sk_package[32] = {0};
	printf("TA2_Opensession\n");
	return TEE_SUCCESS;
}

static TEE_Result ta2_sm2_test(uint32_t param_types, TEE_Param params[4])
{
	// ta normal check (by liu)
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	TEE_Result res;
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	// read from struct param(by liu)
	SM9Params_init(&BN);
	struct sm9_context sm9_test;
	sm9_reset_ctx(&sm9_test);
 	sm9_set_r(&sm9_test);
	struct ecc_context ecc_test;
	sm9_set_para(&ecc_test, 1, 0);
	size_t sm2_in_sz, sm2_out_sz;
	unsigned char* sm2_in;
	unsigned char* sm2_out;
	sm2_in_sz = params[0].memref.size;
	sm2_in = TEE_Malloc(sm2_in_sz,0);
	if(!sm2_in)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(sm2_in, params[0].memref.buffer, sm2_in_sz);
	sm2_out_sz = params[1].memref.size;
	sm2_out = TEE_Malloc(sm2_out_sz,0);
	if(!sm2_out)
		return TEE_ERROR_OUT_OF_MEMORY;

	sm2_en(ecc_test, sm2_in, sm2_out);

	TEE_MemMove(params[1].memref.buffer,sm2_out, sm2_out_sz);
	// // sm2_de(ecc_test, output1, output2);
	//TEE_CloseObject(object);
	TEE_Free(sm2_in);
	TEE_Free(sm2_out);
	return res;
}

static TEE_Result ta2_sm9_dkey_R(uint32_t param_types, TEE_Param params[4])
{
	// ta normal check (by liu)
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_NONE);
	TEE_Result res;
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	// read from struct param(by liu)
	SM9Params_init(&BN);
	struct sm9_context sm9_test;
	sm9_reset_ctx(&sm9_test);
	sm9_set_r(&sm9_test);
	struct ecc_context ecc_test;
	size_t ra_sz, da_sz;
	unsigned char* ida;
	unsigned char* rida;
	unsigned char* idb;
	unsigned char* ridb;
	unsigned char* ra;
	unsigned char* ppube;
	unsigned char* kid;
	unsigned char* enpkey;
	unsigned char pkey[128];
	unsigned char dakey[128];
	ida = TEE_Malloc(8, 0);
	idb = TEE_Malloc(8, 0);
	rida = TEE_Malloc(8, 0);
	ridb = TEE_Malloc(8, 0);
	ppube = TEE_Malloc(32, 0);
	enpkey = TEE_Malloc(128, 0);
	kid = TEE_Malloc(16, 0);
	if (!ida || !idb||!ppube||!enpkey||!kid||!rida||!ridb)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(ida, params[0].memref.buffer, 8);
	TEE_MemMove(rida, params[0].memref.buffer+8, 8);
	TEE_MemMove(idb, params[0].memref.buffer+8+8, 8);
	TEE_MemMove(ridb, params[0].memref.buffer+8+8+8, 8);
	
	TEE_MemMove(ppube, params[1].memref.buffer, 32);
	TEE_MemMove(kid, params[1].memref.buffer+32, 16);
	TEE_MemMove(enpkey, params[1].memref.buffer+32+16, 128);
	sm9_set_para(&ecc_test, 0, ppube);
	for(int i=0;i<32;i++){
		printf("\n%02X",ppube[i]);
	}
	for(int i=0;i<8;i++){
		printf("\n%02X %02X %02X %02X",ida[i],idb[i],rida[i],ridb[i]);
	}
	
	//func part
	TEE_Time time1,time2,time3,time4;
	TEE_GetSystemTime(&time1);
	printf("\nsuccessful value4.1");
	printf("\nsuccessful value4.2");
	uint8_t IDA1[] = {0x01,0x23,0x45,0x67,0x76,0x54,0x32,0x10};
	sm9_key_generation(ecc_test, ida, 8, dakey);
	for(int i=0;i<128;i++){
		printf("\n%02X",dakey[i]);
	}
	TEE_GetSystemTime(&time2);
	//caculate pkey
	printf("\nsuccessful value5");
	printf("\nsuccessful value6");

	sm4_ecb_decryption(enpkey, 128, kid, pkey);
	for(int i=0;i<128;i++){
		printf("\n%02X",pkey[i]);
	}
	printf("\nsuccessful value7");
	printf("\nsuccessful value8");
	//set the ppube
	Cnode_init(&head1, &tail1, ida, rida, kid, pkey);
	return res;
	for(int i=0;i<12;i++){
		printf("\n%02X",head1.pkey[i]);
	}
	//caculate ra
	TEE_GetSystemTime(&time3);
	ra = TEE_Malloc(64, 0);
	//sm9_userA_exchangeR(&sm9_test, ecc_test, ida, rida, idb, ridb, ra);
	TEE_GetSystemTime(&time4);
	// ra_sz = params[2].memref.size;
	// for(int i=0;i<64;i++){
	// 	printf("\n%02X",ra[i]);
	// }
	if (!ra)
		return TEE_ERROR_OUT_OF_MEMORY;
	// // sm2_de(ecc_test, output1, output2);
	//TEE_CloseObject(object);
	TEE_Free(ra);
	TEE_Free(ida);
	TEE_Free(rida);
	TEE_Free(idb);
	TEE_Free(ridb);
	TEE_Free(ppube);
	TEE_Free(pkey);
	TEE_Free(enpkey);
	TEE_Free(kid);
	TEE_Free(dakey);
	printf("second1 is %d\n",time1.seconds);
	printf("millis1 is %d\n",time1.millis);
	printf("second2 is %d\n",time2.seconds);
	printf("millis2 is %d\n",time2.millis);
	return res;
}

TEE_Result ta2_Context_Hmac(uint32_t param_types, TEE_Param params[4])
{
	// printf("\nStart\n");
	// ta normal check (by liu)
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT);
	TEE_Result res;
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	// printf("\nStart end\n");
	char *data;
	uint8_t cur_id[ID_LEN];
	uint8_t hmac_value[32];
	uint8_t *encontext;
	uint8_t *sm4context;
	uint8_t *secure_read_flag;
	struct msg_context *msg_c;
	msg_c  = (struct msg_context *)TEE_Malloc(sizeof(struct msg_context), 0);
	size_t data_len = params[0].memref.size;
	size_t encontext_len = params[1].memref.size;
	data = TEE_Malloc(data_len, 0);
	encontext = TEE_Malloc(encontext_len, 0);
	sm4context = TEE_Malloc(encontext_len, 0);
	secure_read_flag = TEE_Malloc(1, 0);
	// printf("\nMalloc\n");
	if(!data|| !encontext|| !sm4context)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(data, params[0].memref.buffer, data_len);
	TEE_MemMove(cur_id, params[2].memref.buffer, ID_LEN);
	TEE_MemMove(secure_read_flag, params[3].memref.buffer, 1);
	// printf("\nMemMove Finsh\n");
	// main function part 
	msg_context_init(msg_c, data, data_len);
	//struct otp_context* otp_c;
	int cur_pos = otp_cons_search(otp_cons, 5, cur_id);
	// printf("\nta read flag:%d\n", *secure_read_flag);
	if(otp_cons[cur_pos] == NULL || *secure_read_flag){
		// printf("\nFirst\n");
		//首次内容认证：新建otp结构体 安全文件读取 otp结构体初始化
		if(otp_cons[cur_pos] != NULL){
			TEE_Free(otp_cons[cur_pos]);
		}
		otp_c  = (otp_context *)TEE_Malloc(sizeof(otp_context), 0);
		otp_cons[cur_pos] = otp_c;
		// uint8_t package[32] = {0};
		// secure_read(cur_id, package);
		// uint8_t seed[] = {0x01,0x02,0x03,0x04};
		// uint8_t id[8], rid[8];
		// uint8_t sk[16];
		// memmove(id, package, 8);
		// memmove(rid, package+8, 8);
		// memmove(sk, package+8+8, 16);
		uint8_t seed[] = {0x01,0x02,0x03,0x04};
		uint8_t id[8], rid[8];
		uint8_t sk[16];
		memmove(id, first_sk_package, 8);
		memmove(rid, first_sk_package+8, 8);
		memmove(sk, first_sk_package+8+8, 16);
		otp_context_init(otp_c, id, rid, sk, seed, COUNTS);
	}else{
		//非首次内容认证：直接读取上次结构体即可
		otp_c = otp_cons[cur_pos];
	}
	//printf("\noriginal sk:\n");
	//format_print(otp_c->SK, 16);
	otp_context_hmac(otp_c, msg_c, hmac_value);
	//// need to add timestamp
	//printf("Hmac:\n");
	//format_print(msg_c->Hmac, 32);
	int m = data_len/10;
	int n = data_len - m*10;
	char ten = m+'0';
	char one = n+'0';
	TEE_MemMove(encontext, &ten, 1);
	//printf("wrong6!\n");
	TEE_MemMove(encontext+1, &one, 1);
	//printf("wrong6!\n");	
	TEE_MemMove(encontext+1+1, msg_c->Msg, 62);
	//printf("wrong6!\n");
	//printf("wrong7!\n");
	TEE_MemMove(encontext+1+1+62, msg_c->Hmac, 32);
	//printf("wrong8!\n");
	sm4_ecb_encryption(encontext, encontext_len, otp_c->SK, sm4context);
	//printf("wrong9!\n");
	printf("\nsk:\n");
	format_print(otp_c->SK, 16);
	TEE_MemMove(params[1].memref.buffer, sm4context, encontext_len);
	TEE_Free(data);
	TEE_Free(encontext);
	TEE_Free(sm4context);
	temp_msg_c = msg_c;
	return res;
}

TEE_Result ta2_Secure_Read(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	TEE_Result res;
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	uint8_t oppo_id[8];
	TEE_MemMove(oppo_id, params[0].memref.buffer, 8);
	secure_read(oppo_id, first_sk_package);
	return res;
}


TEE_Result ta2_Context_Update(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	TEE_Result res;
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	uint8_t update_flag[4];
	update_flag[0] = 0x00;
	TEE_MemMove(update_flag, params[0].memref.buffer, 4);
	if(update_flag[0] == 0x01){
		//printf("original sk:\n");
		// format_print(otp_c->SK, 16);
		int big_update_flag = otp_context_update(otp_c, *temp_msg_c);
		if(big_update_flag == 1){
			// uint8_t package[32] = {0};
			// secure_read(otp_c->id, package);
			// uint8_t seed[] = {0x01,0x02,0x03,0x04};
			// uint8_t id[8], rid[8];
			// uint8_t sk[16];
			// memmove(id, package, 8);
			// memmove(rid, package+8, 8);
			// memmove(sk, package+8+8, 16);
			//printf("\nbukeneng\n");
			uint8_t seed[] = {0x01,0x02,0x03,0x04};
			uint8_t id[8], rid[8];
			uint8_t sk[16];
			memmove(id, first_sk_package, 8);
			memmove(rid, first_sk_package+8, 8);
			memmove(sk, first_sk_package+8+8, 16);
			//printf("\nta_update_test1\n");
			otp_context_init(otp_c, id, rid, sk, seed, COUNTS);
			//printf("update sk:\n");
			//format_print(otp_c->SK, 16);
			//printf("\nSk timely update successful!\n");	
		}else{
			printf("update sk:\n");
			format_print(otp_c->SK, 16);
			// printf("\nSk TOTP update successful!\n");
			// printf("\nkeneng\n");
			//printf("\nta_update_test1\n");
		}
		//printf("\nSk TOTP update successful!\n");
	}
	else
	{
		otp_c->Counts--;
	}
	otp_c = NULL;
	TEE_Free(temp_msg_c);
	temp_msg_c = NULL;
}

TEE_Result ta2_Context_DeHmac(uint32_t param_types, TEE_Param params[4])
{
	// ta normal check (by liu)
	//printf("wrong1!\n");
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT);
	TEE_Result res;
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	//printf("wrong1!\n");
	char *dedata;
	uint8_t hmac_value[32];
	uint8_t cur_id[ID_LEN];
	uint8_t *encontext;
	uint8_t *sm4context;
	uint8_t *secure_read_flag;
	//// need to add more params
	//printf("wrong1!\n");
	struct msg_context server_msg_c;

	size_t encontext_len = params[0].memref.size;
	size_t dedata_len = params[1].memref.size;
	dedata = TEE_Malloc(dedata_len, 0);
	encontext = TEE_Malloc(encontext_len, 0);
	sm4context = TEE_Malloc(encontext_len, 0);
	secure_read_flag = TEE_Malloc(1, 0);
	if(!dedata|| !encontext|| !sm4context)
		return TEE_ERROR_OUT_OF_MEMORY;
	//printf("wrong1!\n");
	TEE_MemMove(encontext, params[0].memref.buffer, encontext_len);
	TEE_MemMove(cur_id, params[2].memref.buffer, ID_LEN);
	TEE_MemMove(secure_read_flag, params[3].memref.buffer, 1);
	//48+32

	int cur_pos = otp_cons_search(otp_cons, 5, cur_id);
	if(otp_cons[cur_pos] == NULL || *secure_read_flag){
		//首次内容认证：新建otp结构体; 安全文件读取; otp结构体初始化
		if(otp_cons[cur_pos] != NULL){
			TEE_Free(otp_cons[cur_pos]);
		}
		server_otp_c  = (otp_context *)TEE_Malloc(sizeof(otp_context), 0);
		otp_cons[cur_pos] = server_otp_c;
		// uint8_t package[32] = {0};
		// secure_read(cur_id, package);
		// uint8_t seed[] = {0x01,0x02,0x03,0x04};
		// uint8_t id[8], rid[8];
		// uint8_t sk[16];
		// memmove(id, package, 8);
		// memmove(rid, package+8, 8);
		// memmove(sk, package+8+8, 16);
		
		uint8_t seed[] = {0x01,0x02,0x03,0x04};
		uint8_t id[8], rid[8];
		uint8_t sk[16];
		memmove(id, first_sk_package, 8);
		memmove(rid, first_sk_package+8, 8);
		memmove(sk, first_sk_package+8+8, 16);
		otp_context_init(server_otp_c, id, rid, sk, seed, COUNTS);
	}else{
		//非首次内容认证：直接读取上次结构体即可
		server_otp_c = otp_cons[cur_pos];
	}
	sm4_ecb_decryption(encontext, encontext_len, server_otp_c->SK, sm4context);
	//UNPACKAGING
	int m, n, data_size;
	char ten,one;
	TEE_MemMove(&ten,sm4context,1);
	TEE_MemMove(&one,sm4context+1,1);
	m = ten -'0'; 
	n = one -'0';
	data_size = m*10+n;
	// printf("\nDE_datasize:\n");
	// printf("%d", data_size);
	//
	if(data_size >= 64 || data_size <= 0){
		uint8_t rec_valid1[] = {0x01, 0x00};
		TEE_MemMove(params[1].memref.buffer, rec_valid1+1, 1);
		TEE_MemMove(params[1].memref.buffer+1, sm4context, 1);
		TEE_MemMove(params[1].memref.buffer+2, sm4context+1, 1);
		//TEE_MemMove(params[1].memref.buffer+3, dedata, data_size);
		//printf("\nContext identify defeat!\n");
		TEE_Free(dedata);
		TEE_Free(encontext);
		TEE_Free(sm4context);
		server_otp_c = NULL;
		return res;
	}
	TEE_MemMove(dedata, sm4context+2, data_size);
	msg_context_init(&server_msg_c, dedata, data_size);
	int k = 0;
	if((2+data_size)%16==0)
		k = (2+data_size)/16;
	else
		k = 16*((2+data_size)/16+1);
	k = 64;
	TEE_MemMove(server_msg_c.Hmac, sm4context+k, 32);
	//printf("\nHmac:\n");
	//format_print(server_msg_c.Hmac, 32);
	int flag = otp_context_equal(server_otp_c, &server_msg_c);
	uint8_t rec_valid[] = {0x01, 0x00};

	if(flag)
	{
		TEE_MemMove(params[1].memref.buffer, rec_valid, 1);
		TEE_MemMove(params[1].memref.buffer+1, sm4context, 1);
		TEE_MemMove(params[1].memref.buffer+2, sm4context+1, 1);
		TEE_MemMove(params[1].memref.buffer+3, dedata, data_size);
		//printf("\nContext identify successful!\n");
	}
	else
	{
		TEE_MemMove(params[1].memref.buffer, rec_valid+1, 1);
		TEE_MemMove(params[1].memref.buffer+1, sm4context, 1);
		TEE_MemMove(params[1].memref.buffer+2, sm4context+1, 1);
		//TEE_MemMove(params[1].memref.buffer+3, dedata, data_size);
		//server_otp_c->Counts--;
		TEE_Free(dedata);
		TEE_Free(encontext);
		TEE_Free(sm4context);
		server_otp_c = NULL;
		return res;
		//printf("\nContext identify defeat!\n");
	}

	printf("\noriginal_sk:\n");
	format_print(server_otp_c->SK, 16);
	int big_update_flag = otp_context_update(server_otp_c, server_msg_c);
	//int big_update_flag = otp_context_update(otp_c, *temp_msg_c);
	if(big_update_flag == 1){
		// uint8_t package[32] = {0};
		// secure_read(server_otp_c->id, package);
		// uint8_t seed[] = {0x01,0x02,0x03,0x04};
		// uint8_t id[8], rid[8];
		// uint8_t sk[16];
		// memmove(id, package, 8);
		// memmove(rid, package+8, 8);
		// memmove(sk, package+8+8, 16);

		uint8_t seed[] = {0x01,0x02,0x03,0x04};
		uint8_t id[8], rid[8];
		uint8_t sk[16];
		memmove(id, node1.id, 8);
		memmove(rid, node1.rid, 8);
		memmove(sk, node1.sk, 16);
		otp_context_init(server_otp_c, id, rid, sk, seed, COUNTS);
		printf("update sk: \n");
		format_print(server_otp_c->SK, 16);
		printf("\nSk timely update successful!\n");
	}else{
		printf("update sk: \n");
		format_print(server_otp_c->SK, 16);
		printf("\nSk TOTP update successful!\n");
	}
	//TEE_MemMove(params[1].memref.buffer+42, server_otp_c->SK, 16);
	TEE_Free(dedata);
	TEE_Free(encontext);
	TEE_Free(sm4context);
	server_otp_c = NULL;
	return res;
}



void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
	printf("closeTA2session!\n");
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx,
			uint32_t __unused cmd_id,
			uint32_t __unused param_types,
			TEE_Param __unused params[4])
{
	switch (cmd_id)
	{
	case TA2_SM2_TEST:
		return ta2_sm2_test(param_types,params);
	case TA2_SM9_DKEY_R:
	    return ta2_sm9_dkey_R(param_types,params);
	case TA2_CONTEXT_HMAC:
		return ta2_Context_Hmac(param_types,params);
	case TA2_CONTEXT_DEHMAC:
		return ta2_Context_DeHmac(param_types, params);
	case TA2_CONTEXT_UPDATE:
		return ta2_Context_Update(param_types, params);
	case TA2_SECURE_READ:
		return ta2_Secure_Read(param_types, params);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}