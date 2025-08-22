//
// Created by xy on 11/11/21.
//

#include "sm2.h"

void sm2_set_str(struct sm2_context *ctx, uint8_t *input)
{
    ctx->strLen = 16;
    TEE_MemMove(ctx->str, input, ctx->strLen);
}

void sm2_set_stren(struct sm2_context *ctx, uint8_t *input)
{
    ctx->enLen = 112;
    TEE_MemMove(ctx->str_en, input, ctx->enLen);
}

/*
 *	ecc		
 *	ctx
 */
int sm2_encryption(struct sm2_context *ctx, struct ecc_context ecc)
{
    int i;
    uint8_t C1[64], C2[16], C3[32];
    
    //C1
    CBigInt kr;
    BNPoint C1_BN, nPb, S;
    //need random, cheak in sm2 word
    Get(&kr, (char *)"6D3B497153E3E92524E5C122682DBDC8705062E20B917A5F8FCDB8EE4C66663D", HEX);
    //Get(&kr, rand_Char(64), HEX);
    P_multiply(&C1_BN, ecc.P1, kr);
    P_normorlize(&C1_BN, C1_BN);
    PtoByte(C1, C1_BN);
    //P_toString(C1_BN, P1str, HEX);
    //convert_StrToUnChar(P1str, C1, 128);
    
    
    //C2
    BYTE msg[64], t[16];
    P_multiply(&nPb, ecc.Ppube, kr);
    P_normorlize(&nPb, nPb);
    Get(&kr, (char*)"1", HEX);
    P_multiply(&S, ecc.Ppube, kr);
    P_normorlize(&S, S);
    if(S.z.m_ulValue == 0)
    {
        printf("Error: sm2 BN point S is ∞! \n");
        return 0;
    }
    PtoByte(msg, nPb);
    //P_toString(nPb, P1str, HEX);
    //convert_StrToUnChar(P1str, msg, 128);
    KDF(t, msg, 64, 16*8);
    for(i=0; i<ctx->strLen; i++)
    {
        if(t[i] | 0x00)
            break;
        printf("Error: t is all-0-bit strings!\n");
        return 0;
    }
    Bytes_XOR(C2, (BYTE *)ctx->str, t, 16);
    
    //C3
    BYTE msg_2[128];
    TEE_MemMove(msg_2, msg, 32);
    TEE_MemMove(msg_2+32, ctx->str, ctx->strLen);
    TEE_MemMove(msg_2+32+ctx->strLen, msg+32, 32);
    sm3(msg_2, (ctx->strLen+64), C3);
    
    //C = (C1||C2||C3)
    TEE_MemMove(ctx->str_en, C1, 64);
    TEE_MemMove(ctx->str_en+64, C2, 16);
    TEE_MemMove(ctx->str_en+64+16, C3, 32);
    ctx->enLen=64+32+16;
    
    return 1;
}

/*
 *	ecc		
 *	ctx
 */
int sm2_decryption(struct sm2_context *ctx, struct ecc_context ecc)
{
    int i;
    char x[65], y[65];
    BYTE C1[64], C2[16], C3[32];
    CBigInt kr, x_big, y_big, z_big;
    BNPoint C1_BN, C2_BN, S;
    
    TEE_MemMove(C1, ctx->str_en, 64);
    TEE_MemMove(C2, ctx->str_en+64, 16);
    TEE_MemMove(C3, ctx->str_en+64+16, 32);
    
    //B1 B2
    convert_UnCharToStr(x, C1, 32);
    convert_UnCharToStr(y, C1+32, 32);
    Get(&x_big, x, HEX);
    Get(&y_big, y, HEX);
    Get(&z_big, (char*)"1", HEX);
    P_construct(&C1_BN, x_big, y_big, z_big);
    Get(&kr, (char*)"1", HEX);
    P_multiply(&S, C1_BN, kr);
    P_normorlize(&S, S);
    if(S.z.m_ulValue == 0)
    {
        printf("Error: sm2 BN point S is ∞! \n");
        return 0;
    }
    
    //B3 B4
    BYTE x2y2[64], t[16];
    P_multiply(&C2_BN, C1_BN, ecc.Ke);
    P_normorlize(&C2_BN, C2_BN);
    PtoByte(x2y2, C2_BN);
    //P_toString(C2_BN, P1str, HEX);
    //convert_StrToUnChar(P1str, x2y2, 128);
    KDF(t, x2y2, 64, 16*8);
    for(i=0; i<16; i++)
    {
        if(t[i] | 0x00)
            break;
        printf("Error: sm2 t is zero, break!\n");
        return 0;
    }
    
    //B5
    BYTE M[16];
    Bytes_XOR(M, C2, t, 16);
    
    //B6
    BYTE msg_2[128], u[32];
    TEE_MemMove(msg_2, x2y2, 32);
    TEE_MemMove(msg_2+32, M, 16);
    TEE_MemMove(msg_2+32+16, x2y2+32, 32);
    sm3(msg_2, 16+64, u);
    if(TEE_MemCompare(u, C3, 16))
    {
        printf("Error: sm2 t is zero, break!\n");
        return 0;
    }
    
    TEE_MemMove(ctx->str, M, 16);
    ctx->strLen =16;
    return 1;
}

int sm2_en(struct ecc_context ecc, uint8_t *input, uint8_t *output)
{
    int res;
    struct sm2_context ctx;
    sm2_set_str(&ctx, input);
    res = sm2_encryption(&ctx, ecc);
    TEE_MemMove(output, ctx.str_en, ctx.enLen);
    return res;
}

int sm2_de(struct ecc_context ecc, uint8_t *input, uint8_t *output)
{
    int res;
    struct sm2_context ctx;
    sm2_set_stren(&ctx, input);
    res = sm2_decryption(&ctx, ecc);
    TEE_MemMove(output, ctx.str, ctx.strLen);
    return res;
}

