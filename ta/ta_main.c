// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <stdio.h>
#include <stdlib.h>
#include "talib1.h"
#include "kem.h"
#include "sign.h"
#include "keyfind.h"
#include "mtwister.h"
#include <bn_pairing.h>
#include <tee_internal_api.h>
#include <libs_ta.h>
#include "utility.h"
#include "string.h"
#define TA_SECURE_STORAGE_UUID \
		{ 0xf4e750bb, 0x1437, 0x4fbf, \
			{ 0x87, 0x85, 0x8d, 0x35, 0x80, 0xc3, 0x49, 0x94 } }

#define TA_SECURE_STORAGE_CMD_READ_RAW		0
#define TA_SECURE_STORAGE_CMD_WRITE_RAW		1
#define TA_SECURE_STORAGE_CMD_DELETE		2

#define MLEN 59
#define NTESTS 10000

uint8_t Kem_Pk[CRYPTO_PUBLICKEYBYTES];
uint8_t Kem_Sk[CRYPTO_SECRETKEYBYTES];
uint8_t Self_Sig_Pk[CRYPTO_PUBLICKEYBYTES_SIG];
uint8_t Self_Sig_Sk[CRYPTO_SECRETKEYBYTES_SIG];

TEE_Result TA_CreateEntryPoint(void)
{
	// size_t i, j;
  	// int ret;
  	// size_t mlen, smlen;
  	// uint8_t b;
  	// uint8_t m[MLEN + CRYPTO_BYTES_SIG];
  	// uint8_t m2[MLEN + CRYPTO_BYTES_SIG];
  	// uint8_t sm[MLEN + CRYPTO_BYTES_SIG];
  	// uint8_t pk[CRYPTO_PUBLICKEYBYTES_SIG];
  	// uint8_t sk[CRYPTO_SECRETKEYBYTES_SIG];
	
	// uint32_t ta_create_seed = 0;
	// uint8_t ta_create_seeds[] = {0x01, 0x02, 0x03, 0x04};
	// memmove(&ta_create_seed, ta_create_seeds, 4);
	// RandomGen(ta_create_seed, MLEN, m);
	// crypto_sign_keypair(pk, sk);
    // crypto_sign(sm, &smlen, m, MLEN, sk);
    // ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);

    // if(ret) {
    //   printf("Verification failed\n");
    // }
    // if(smlen != MLEN + CRYPTO_BYTES_SIG) {
    //   printf("Signed message lengths wrong\n");
    // }
    // if(mlen != MLEN) {
    //   printf("Message lengths wrong\n");
    // }
    // for(j = 0; j < MLEN; ++j) {
    //   if(m2[j] != m[j]) {
    //     printf("Messages don't match\n");
    //   }
    // }
	// printf("\nm2:\n");
	// format_print(m2, 32);
	// printf("\nm:\n");
	// format_print(m, 32);
	// printf("\nverify_succeed.\n");

	printf("TA_CreateEntryPoint()\n");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	printf("TA_DestroyEntryPoint()\n");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
		TEE_Param __unused params[4],
		void __unused **sess_ctx)
{
	printf("TA_OpenSession()\n");
	// uint8_t pk[CRYPTO_PUBLICKEYBYTES];
	// uint8_t sk[CRYPTO_SECRETKEYBYTES];
	// uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  	// uint8_t key_a[CRYPTO_BYTES];
  	// uint8_t key_b[CRYPTO_BYTES];
	
	// int ret = crypto_kem_keypair(pk, sk);
	// ret = crypto_kem_enc(ct, key_b, pk);
	// ret = crypto_kem_dec(key_a, ct, sk);
	// if(memcmp(key_a, key_b, CRYPTO_BYTES)) {
    // 	printf("ERROR keys\n");
  	// }
	// printf("Crypto successful!\n");
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
	printf("TA_CloseSession()\n");
}


void secure_write()
{
	TEE_Result res1;
	TEE_TASessionHandle sess;
	TEE_UUID uuid = TA_SECURE_STORAGE_UUID;
	uint32_t time=10;
	uint32_t ret_origin;
	uint32_t param_types1;
	TEE_Param params1[4];
	//// TCP datapackage
	uint8_t package[32];
	uint8_t package_id[8];
	TEE_MemMove(package_id, node1.id, 8);
	TEE_MemMove(package, node1.id, 8);
	TEE_MemMove(package+8, node1.rid, 8);
	TEE_MemMove(package+16, node1.sk, 16);
	printf("\nSK storage start:\n");
	printf("storage_id:\n");
	format_print(package_id, 8);
	printf("storage_package:\n");
	format_print(package, 32);
	// printf("\npackage:\n");
	// format_print(package, 32);
	param_types1 = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	params1[0].memref.buffer = package_id;
	params1[0].memref.size = 8;
	params1[1].memref.buffer = package;
	params1[1].memref.size = 32;
	res1 = TEE_OpenTASession(&uuid, time, param_types1, params1, &sess, &ret_origin);
	if (res1 != TEE_SUCCESS)
		printf("TEE_Opensession failed with code 0x%x origin 0x%x",
			res1, ret_origin);
	//printf("\nwrong6\n");
	res1 = TEE_InvokeTACommand(sess,time, TA_SECURE_STORAGE_CMD_WRITE_RAW, param_types1,params1,&ret_origin);
	if (res1 != TEE_SUCCESS)
		printf( "TEE_Invokecommand failed with code 0x%x origin 0x%x",
			res1, ret_origin);
	// for(int i=0;i<16;i++){
	// 	printf("%02x  ",read[i]);
	// }
	printf("\nSk storage successful!\n");
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
}


//get ppube encrypt the kid(by law)
TEE_Result ta_identify_enkid(uint32_t param_types, TEE_Param params[4])
{
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
	uint8_t* ppube;
	uint8_t* enkid;
	uint8_t kid[16];
	size_t ppube_len = params[0].memref.size;
	size_t enkid_len = params[1].memref.size;
	ppube = TEE_Malloc(ppube_len, 0);
	enkid = TEE_Malloc(enkid_len, 0);
	if(!ppube||!enkid)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(ppube, params[0].memref.buffer, ppube_len);
	sm9_set_para(&ecc_n, 0, ppube);
	///NORMAL
	TEE_GenerateRandom(kid, 16);
	// printf("\nkid:\n");
	// for(int i=0;i<16;i++){
	// 	printf("%02X ",kid[i]);
	// }
	///KID FOR TEST, kid is right
	TEE_MemMove(node1.kid, kid, 16);
	sm2_en(ecc_n, kid, enkid);
	// printf("\nenkid:\n");
	// format_print(enkid, 112);
	// printf("\n");
	TEE_MemMove(params[1].memref.buffer, enkid, enkid_len);
	TEE_Free(ppube);
	TEE_Free(enkid);
	return res;
}

TEE_Result ta_identify_depkey(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);
			//TEE_PARAM_TYPE_NONE);
	TEE_Result res;
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	// read from struct param(by liu)
	uint8_t *enpkey;
	uint8_t *pkey;
	uint8_t *kid;
	size_t enpkey_len = params[0].memref.size;
	size_t pkey_len = enpkey_len;
	enpkey = TEE_Malloc(enpkey_len, 0);
	pkey = TEE_Malloc(pkey_len, 0);
	kid = TEE_Malloc(16, 0);
	if(!kid || !enpkey || !pkey)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(kid, node1.kid, 16);
	TEE_MemMove(enpkey, params[0].memref.buffer, enpkey_len);
	sm4_ecb_decryption(enpkey, enpkey_len, kid, pkey);
	TEE_MemMove(node1.pkey, pkey, pkey_len);
	printf("\npkey:\n");
	format_print(pkey, pkey_len);
	printf("\nkid:\n");
	format_print(kid, 16);
	printf("\nenpkey:\n");
	format_print(enpkey, enpkey_len);
	TEE_Free(enpkey);
	TEE_Free(pkey);
	TEE_Free(kid);
	return res;
}

TEE_Result ta_identify_exchangeR(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_NONE);
			//TEE_PARAM_TYPE_NONE);
	TEE_Result res;
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	// read from struct param(by liu)
	sm9_reset_ctx(&sm9_n);
	sm9_set_r(&sm9_n);
	uint8_t *ida;
	uint8_t *idb;
	uint8_t *rida;
	uint8_t *ridb;
	uint8_t *ra;
	size_t ra_len = params[1].memref.size;
	ida = TEE_Malloc(8, 0);
	idb = TEE_Malloc(8, 0);
	rida = TEE_Malloc(8, 0);
	ridb = TEE_Malloc(8, 0);
	ra = TEE_Malloc(ra_len, 0);
	if(!ida|| !idb || !rida || !ridb ||!ra )
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(ida, params[0].memref.buffer, 8);
	TEE_MemMove(rida, params[0].memref.buffer+8, 8);
	TEE_MemMove(idb, params[0].memref.buffer+8+8, 8);
	TEE_MemMove(ridb, params[0].memref.buffer+8+8+8, 8);
	
	
	uint8_t c_or_s_flag[4];
	TEE_MemMove(c_or_s_flag, params[2].memref.buffer, 4);
	if(c_or_s_flag[0] == 0x01){
		sm9_userA_exchangeR(&sm9_n, ecc_n, ida, rida, idb, ridb, ra);
	}else{
		sm9_userB_exchangeR(&sm9_n, ecc_n, idb, ridb, ida, rida, ra);
	}
	TEE_MemMove(params[1].memref.buffer, ra, ra_len);
	//存对端节点的id和rid
	TEE_MemMove(node1.id, idb, 8);
	TEE_MemMove(node1.rid, ridb, 8);
	TEE_Free(ida);
	TEE_Free(idb);
	TEE_Free(rida);
	TEE_Free(ridb);
	TEE_Free(ra);
	return res;
}

TEE_Result ta_identify_Gensk_S(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_NONE
			//TEE_PARAM_TYPE_MEMREF_OUTPUT,
			//TEE_PARAM_TYPE_MEMREF_INPUT
			);
	TEE_Result res;
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	// read from struct param(by liu)
	uint8_t *rb;
	uint8_t *pkey;
	uint8_t *sa;
	uint8_t *ska;
	
	size_t pkey_len = 128;
	size_t rb_len = params[0].memref.size;
	size_t sa_len = params[1].memref.size;
	size_t ska_len = 16;
	rb = TEE_Malloc(rb_len, 0);
	pkey = TEE_Malloc(pkey_len, 0);
	ska = TEE_Malloc(ska_len, 0);
	sa = TEE_Malloc(sa_len, 0);
	if(!rb || !pkey || !ska|| !sa)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(rb, params[0].memref.buffer, rb_len);
	TEE_MemMove(pkey, node1.pkey, pkey_len);

	uint8_t c_or_s_flag[4];
	TEE_MemMove(c_or_s_flag, params[2].memref.buffer, 4);
	if(c_or_s_flag[0] == 0x01){
		sm9_userA_exchangeSK(&sm9_n, ecc_n, pkey, rb, ska);
		sm9_userA_exchangeS(&sm9_n, sa);
	}else{
		sm9_userB_exchangeSK(&sm9_n, ecc_n, pkey, rb, ska);
		sm9_userB_exchangeS(&sm9_n, sa);
	}
	TEE_MemMove(params[1].memref.buffer, sa, sa_len);
	TEE_MemMove(node1.sk, ska, ska_len);
	printf("\nsk: \n");
	format_print(ska, 16);
	//////  SEND IDRID SK TO TA2 BY SECRUITY_STORAGE
	// secure_write();
	TEE_Free(rb);
	TEE_Free(ska);
	TEE_Free(sa);
	TEE_Free(pkey);
	return res;
}

TEE_Result ta_identify_Confirm_S(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_NONE
			//TEE_PARAM_TYPE_MEMREF_OUTPUT,
			//TEE_PARAM_TYPE_MEMREF_INPUT
			);
	TEE_Result res;
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	uint8_t *sb;
	sb = TEE_Malloc(32, 0);
	//result = TEE_Malloc(1, 0);
	if(!sb){
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	TEE_MemMove(sb, params[0].memref.buffer, 32);
	uint8_t add[4] = {0x01, 0x00, 0x01, 0x00};
	int flag;
	printf("\nS1:\n");
	format_print(sb, 32);
	printf("\nS2:\n");
	uint8_t c_or_s_flag[4];
	TEE_MemMove(c_or_s_flag, params[2].memref.buffer, 4);
	if(c_or_s_flag[0] == 0x01){
		flag = sm9_userA_exchangeConfirm(sm9_n, sb);
		format_print(sm9_n.SB, 32);
	}else{
		flag = sm9_userB_exchangeConfirm(sm9_n, sb);
		format_print(sm9_n.SA, 32);
	}
	if(flag){
		TEE_MemMove(params[1].memref.buffer, add, 1);
		secure_write();
	}else{
		TEE_MemMove(params[1].memref.buffer, add+1, 1);
	}
	TEE_Free(sb);
	return res;
}

TEE_Result ta_save_opposigpk(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE
			);
	TEE_Result res;
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint8_t oppo_id[ID_LEN];
	uint8_t oppo_sig_pk[CRYPTO_PUBLICKEYBYTES_SIG];
	TEE_MemMove(oppo_id, params[0].memref.buffer, ID_LEN);
	TEE_MemMove(oppo_sig_pk, params[1].memref.buffer, CRYPTO_PUBLICKEYBYTES_SIG);
	
	//save
	sig_data_insert(&sig_node_head, oppo_id, oppo_sig_pk);
}

TEE_Result ta_sig_keypair(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE
			);
	TEE_Result res;
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	uint8_t self_sig_pk[CRYPTO_PUBLICKEYBYTES_SIG];
  	uint8_t self_sig_sk[CRYPTO_SECRETKEYBYTES_SIG];
	crypto_sign_keypair(self_sig_pk, self_sig_sk);
	TEE_MemMove(params[0].memref.buffer, self_sig_pk, CRYPTO_PUBLICKEYBYTES_SIG);
	TEE_MemMove(Self_Sig_Pk, self_sig_pk, CRYPTO_PUBLICKEYBYTES_SIG);
	TEE_MemMove(Self_Sig_Sk, self_sig_sk, CRYPTO_SECRETKEYBYTES_SIG);
	return TEE_SUCCESS;
}

TEE_Result ta_kem_keypair(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE
			);
	TEE_Result res;
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	//kem_keypair
	uint8_t kem_pk[CRYPTO_PUBLICKEYBYTES];
	uint8_t kem_sk[CRYPTO_SECRETKEYBYTES];
	int ret = crypto_kem_keypair(kem_pk, kem_sk);
	TEE_MemMove(Kem_Pk, kem_pk, CRYPTO_PUBLICKEYBYTES);
	TEE_MemMove(Kem_Sk, kem_sk, CRYPTO_SECRETKEYBYTES);
	//sig_kem_pk
	uint8_t sig_msg[CRYPTO_PUBLICKEYBYTES + CRYPTO_BYTES_SIG];
	size_t sig_msg_len;
	uint8_t self_sig_sk[CRYPTO_SECRETKEYBYTES_SIG];
	TEE_MemMove(self_sig_sk, Self_Sig_Sk, CRYPTO_SECRETKEYBYTES_SIG);
	crypto_sign(sig_msg, &sig_msg_len, kem_pk, CRYPTO_PUBLICKEYBYTES, self_sig_sk);
	//return the result
	TEE_MemMove(params[0].memref.buffer, sig_msg, CRYPTO_PUBLICKEYBYTES + CRYPTO_BYTES_SIG);
	return TEE_SUCCESS;
}

TEE_Result ta_authen_encape(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_NONE
			);
	TEE_Result res;
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	
	//sign_verify
	uint8_t oppo_sig_pk[CRYPTO_PUBLICKEYBYTES_SIG];
	uint8_t oppo_id[ID_LEN];
	uint8_t kem_pk[CRYPTO_PUBLICKEYBYTES];
	size_t kem_pk_len;
	uint8_t *sig_msg;
	int ret;
	size_t sig_msg_len = CRYPTO_PUBLICKEYBYTES + CRYPTO_BYTES_SIG;
	sig_msg = TEE_Malloc(sig_msg_len, 0);
	if(!sig_msg)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(sig_msg, params[0].memref.buffer, sig_msg_len);
	TEE_MemMove(oppo_id, params[1].memref.buffer, ID_LEN);
	ret = sig_data_search(&sig_node_head, oppo_id, oppo_sig_pk);
	if(ret) {
      printf("Found failed\n");
	  return -1;
    }
	ret = crypto_sign_open(kem_pk, &kem_pk_len, sig_msg, sig_msg_len, oppo_sig_pk);
	if(ret) {
      printf("Verification failed\n");
	  return -1;
    }

	//encape
	uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
	uint8_t final_key[CRYPTO_BYTES];
	ret = crypto_kem_enc(ct, final_key, kem_pk);
	printf("\nfinal_key:\n");
	format_print(final_key, 16);

	//sign_ct(ciphertext)
	uint8_t *self_sig_sk;
	uint8_t *sig_ct;
	size_t sig_ct_len;
	self_sig_sk = TEE_Malloc(CRYPTO_SECRETKEYBYTES_SIG, 0);
	sig_ct = TEE_Malloc(CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES_SIG, 0);
	if(!self_sig_sk || !sig_ct){
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	TEE_MemMove(self_sig_sk, Self_Sig_Sk, CRYPTO_SECRETKEYBYTES_SIG);
	crypto_sign(sig_ct, &sig_ct_len, ct, CRYPTO_CIPHERTEXTBYTES, self_sig_sk);
	
	//return
	TEE_MemMove(node1.id, oppo_id, 8);
	TEE_MemMove(node1.rid, sig_ct+1000, 8);	
	TEE_MemMove(node1.sk, final_key, 16);
	secure_write();
	TEE_MemMove(params[2].memref.buffer, sig_ct, sig_ct_len);
	TEE_Free(sig_msg);
	TEE_Free(sig_ct);
	TEE_Free(self_sig_sk);
}

TEE_Result ta_authen_decape(uint32_t param_types, TEE_Param params[4])
{
		const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE
			);
	TEE_Result res;
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	//sign_verify
	int ret;
	size_t ct_len;
	size_t sig_ct_len = CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES_SIG;
	uint8_t ct[CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES_SIG];
	uint8_t oppo_id[ID_LEN];
	uint8_t *oppo_sig_pk;
	uint8_t *sig_ct;
	oppo_sig_pk = TEE_Malloc(CRYPTO_PUBLICKEYBYTES_SIG, 0);
	sig_ct = TEE_Malloc(CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES_SIG, 0);
	if(!oppo_sig_pk || !sig_ct){
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	TEE_MemMove(sig_ct, params[0].memref.buffer, CRYPTO_CIPHERTEXTBYTES + CRYPTO_BYTES_SIG);
	TEE_MemMove(oppo_id, params[1].memref.buffer, ID_LEN);
	
	ret = sig_data_search(&sig_node_head, oppo_id, oppo_sig_pk);
	if(ret) {
      printf("Found failed\n");
	  return -1;
    }
	ret = crypto_sign_open(ct, &ct_len, sig_ct, sig_ct_len, oppo_sig_pk);
	if(ret) {
      printf("Verification failed\n");
	  return -1;
    }

	//decape
	uint8_t kem_sk[CRYPTO_SECRETKEYBYTES];
	uint8_t final_key[CRYPTO_BYTES];
	TEE_MemMove(kem_sk, Kem_Sk, CRYPTO_SECRETKEYBYTES);

	ret = crypto_kem_dec(final_key, ct, kem_sk);
	printf("\nfinal_key:\n");
	format_print(final_key, 16);
	
	//return
	TEE_MemMove(node1.id, oppo_id, 8);
	TEE_MemMove(node1.rid, ct+2000, 8);
	TEE_MemMove(node1.sk, final_key, 16);
	secure_write();
	TEE_Free(oppo_sig_pk);
	TEE_Free(sig_ct);
}





TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx,
			uint32_t __unused cmd_id,
			uint32_t __unused param_types,
			TEE_Param __unused params[4])
{
	switch (cmd_id)
	{
	case TA_IDENTIFY_ENKID:
		return ta_identify_enkid(param_types, params);
	case TA_SAVE_OPPOSIGPK:
		return ta_save_opposigpk(param_types, params);
	case TA_SIG_KEYPAIR:
		return ta_sig_keypair(param_types, params);
	case TA_KEM_KEYPAIR://Alice generate pk sk, sign the pk with Ksa
		return ta_kem_keypair(param_types, params);
	case TA_AUTHEN_ENCAPE://Bob verify the pk with Kva, and encape the K, and sign the ciphertext with Ksb
		return ta_authen_encape(param_types, params);
	case TA_AUTHEN_DECAPE://Alice verify the ciphertext with Kvb, and decape the k
		return ta_authen_decape(param_types, params);
	case TA_IDENTIFY_DEPKEY:
		return ta_identify_depkey(param_types, params);
	case TA_IDENTIFY_EXCHANGER:
		return ta_identify_exchangeR(param_types, params);
	case TA_IDENTIFY_GENSK_S:
		return ta_identify_Gensk_S(param_types, params);
	case TA_IDENTIFY_CONFIRM_S:
		return ta_identify_Confirm_S(param_types, params);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}
