//
// Created by xy on 11/23/21.
//

#include "otp.h"

otp_context *otp_cons[5];
otp_context *otp_c, *server_otp_c;
struct msg_context *temp_msg_c;
uint8_t first_sk_package[32];
void msg_context_init(struct msg_context *msg_ctx, char *str, size_t len)
{
    msg_ctx->MLen = len;
    TEE_MemMove(msg_ctx->Msg, str, len);
    TEE_MemFill(msg_ctx->Msg+len, 0, 64-len);
    TEE_MemFill(msg_ctx->Hmac, 0, 32);
}

void msg_context_move(struct msg_context *msg_ctx, struct msg_context msg_ctx_new)
{
    msg_ctx->MLen = msg_ctx_new.MLen;
    TEE_MemMove(msg_ctx->Msg, msg_ctx_new.Msg, 64);
    TEE_MemMove(msg_ctx->Hmac, msg_ctx_new.Hmac, 32);
}

void msg_context_free(struct msg_context *msg_ctx)
{
    TEE_Free(msg_ctx);
}

void otp_context_init(struct otp_context *otp_ctx, uint8_t *id, uint8_t* rid,  uint8_t *sk, uint8_t *seed, size_t i)
{
    TEE_MemMove(otp_ctx->id, id, 8);
    TEE_MemMove(otp_ctx->rid, rid, 8);
    TEE_MemMove(otp_ctx->IDrid, id, 8);
    TEE_MemMove(otp_ctx->IDrid+8, rid, 8);
    TEE_MemMove(otp_ctx->SK, sk, 16);
    TEE_MemMove(otp_ctx->Seed, seed, 4);
    //last_context all zero
    msg_context_init(&otp_ctx->LastContext, (char *)"", 0);
    otp_ctx->Counts = i; 
}

// output 128+32 (Msg||Rng||Hmac)
void otp_context_hmac(struct otp_context *otp_ctx, struct msg_context *msg_ctx, uint8_t *output)
{
    int i;
    uint8_t data[HMAC_DATA_LEN];
    size_t len = HMAC_DATA_LEN;
    TEE_MemMove(data, msg_ctx->Msg, msg_ctx->MLen);
    len = len - msg_ctx->MLen;
    
    //generate random
    uint8_t random[len];
    uint32_t random_seed;
    TEE_MemMove(&random_seed, otp_ctx->Seed, 4);
    RandomGen(random_seed, len, random);
    TEE_MemMove(data+msg_ctx->MLen, random, len);
    // printf("\n Send_seed:\n");
    // printf("%X ", random_seed);
    // printf("\nLEN: %d\nRANDOM: \n", len);

    // for(int i=0; i<len; ++i){
    //     printf("%02X ", random[i]);
    // }
    // printf("\n");
    //Hmac Key
    uint8_t key[16];
    TEE_MemMove(key, otp_ctx->SK, 16);
    for(i = 0; i < 16; i++)
    {
        key[i] = key[i] ^ otp_ctx->LastContext.Hmac[i+16];
    }
    
    sm3_hmac(key, 16, data, HMAC_DATA_LEN, output);
    // printf("\nSENDDATA:\n");
    // for(int i=0;i<16;i++){
	// 	for(int j=0;j<8;j++){
	// 		printf("%02X  ",data[j+i*8]);	
	// 	}
	// 	printf("\n");
	// }
    TEE_MemMove(msg_ctx->Hmac, output, 32);
}

// hmac 128+32 (Msg||Rng||Hmac)
int otp_context_equal(struct otp_context *otp_ctx, struct msg_context *msg_ctx)
{
    int i;
    uint8_t data[HMAC_DATA_LEN];
    size_t len = HMAC_DATA_LEN;
    TEE_MemMove(data, msg_ctx->Msg, msg_ctx->MLen);
    len = len - msg_ctx->MLen;
    
    //generate random
    uint8_t random[len];
    uint32_t random_seed;
    TEE_MemMove(&random_seed, otp_ctx->Seed, 4);
    RandomGen(random_seed, len, random);
    TEE_MemMove(data+msg_ctx->MLen, random, len);
    // printf("\n DE_seed:\n");
    // printf("%X ", random_seed);
    // printf("\nDE_LEN: %d\nDE_RANDOM: \n", len);
    // for(int i=0; i<len; ++i){
    //     printf("%02X ", random[i]);
    // }
    // printf("\n");
    //Hmac Key
    uint8_t key[16];
    TEE_MemMove(key, otp_ctx->SK, 16);
    for(i = 0; i < 16; i++)
    {
        key[i] = key[i] ^ otp_ctx->LastContext.Hmac[i+16];
    }
    
    uint8_t hash[32];
    sm3_hmac(key, 16, data, HMAC_DATA_LEN, hash);
    // printf("\nDEDATA:\n");
    // for(int i=0;i<16;i++){
	// 	for(int j=0;j<8;j++){
	// 		printf("%02X  ",data[j+i*8]);	
	// 	}
	// 	printf("\n");
	// }
    // printf("DeHmac:\n");
    // for(int i=0;i<4;i++){
	// 	for(int j=0;j<8;j++){
	// 		printf("%02X  ",hash[j+i*8]);	
	// 	}
	// 	printf("\n");
	// }	
    return Bytes_Equal(msg_ctx->Hmac, hash, 32);
}
//return_val:  1(update) 0(no_update)
int otp_context_update(struct otp_context *otp_ctx, struct msg_context msg_ctx)
{
    //update msg_ctx
    int i;
    msg_context_move(&otp_ctx->LastContext, msg_ctx);
    
    //update seed
    char cut_c[MSG_DATA_CUTLEN+1];
    TEE_MemMove(cut_c, msg_ctx.Msg+MSG_DATA_CUTPOS, MSG_DATA_CUTLEN);
    // for(int i=0; i<13; i++){
    //     printf("%02X ", cut_c[i]);
    // }
    // CBigInt cut_bn;
    //Get(&cut_bn, cut_c, DEC);
    //char *cut_hex = Put(cut_bn, HEX);
    uint8_t cut_sm3[32];
    sm3(cut_c, MSG_DATA_CUTLEN, cut_sm3);
    // for(int i=0; i<32; i++){
    //     printf("%02X ", cut_sm3[i]);
    // }
    uint8_t cut_seed[4];
    convert_StrToUnChar(cut_sm3 + 24, cut_seed, 8);
    for(i = 0; i < 4; i++){
        otp_ctx->Seed[i] = cut_seed[i];

    }        
    //update sk
    for(i = 0; i < 16; i++)
    {
        otp_ctx->SK[i] = otp_ctx->SK[i] ^ msg_ctx.Hmac[i];
        otp_ctx->SK[i] = otp_ctx->SK[i] ^ msg_ctx.Hmac[i+16];
    }

    otp_ctx->Counts--;
    // printf("\ncount:%d\n", otp_ctx->Counts);
    if(otp_ctx->Counts <= 0){
       return 1; 
    }
    return 0;
}

void otp_cons_init(otp_context **oppo_otp, int len)
{
    printf("\n otp_cons_init_begin!");
    for(int i=0; i<len; ++i){
        oppo_otp[i] = NULL;
    }
    printf("\n otp_cons_init_success!");
}

int otp_cons_search(otp_context **oppo_otp, int len, uint8_t* cur_id)
{
    //printf("\notp_cons_search_begin!");
    int i = 0;
    for(; i<len; ++i){
        if(oppo_otp[i] == NULL) break;
        if(Bytes_Equal(cur_id, oppo_otp[i]->id, 8)){
            break;
        }
    }
    //printf("\notp_cons_search_success!");
    return i;
}
