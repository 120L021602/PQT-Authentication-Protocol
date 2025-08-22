//
// Created by xy on 11/16/21.
//

#include "sm9.h"

/*
 *  ecc 	存储大数和椭圆曲线信息
 *  mode	指定工作状态为验证机或注册机
 *  input	只在 mode 0 中使用，输入注册机从验证机处获得的公钥Ppube
 */
struct sm9_context sm9_n;
struct ecc_context ecc_n;
void sm9_set_para(struct ecc_context *ecc, int mode, uint8_t *input)
{
    CBigInt a, b, c, d, e, f;
    BNField2 b1, b2;

    Get(&a, (char *)"93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD", HEX);
    Get(&b, (char *)"21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616", HEX);
    Get(&c, (char *)"85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141", HEX);
    Get(&d, (char *)"3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B", HEX);
    Get(&e, (char *)"17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96", HEX);
    Get(&f, (char *)"A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7", HEX);
    P_construct_xy(&ecc->P1, a, b);
    F2_construct(&b1, d, c);
    F2_construct(&b2, f, e);
    P2_construct_xy(&ecc->P2, b1, b2);
    
    //mode 1, center; mode 0, node
    if(mode)
    {
        Get(&ecc->Ke, (char *)"02E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F", HEX);	
    	//Get(&ke, rand_Char(64), HEX);
    	P_multiply(&ecc->Ppube, ecc->P1, ecc->Ke);
    	P_normorlize(&ecc->Ppube, ecc->Ppube);
    } else {
    	convert_unCharToBNPoint(input, &ecc->Ppube);
    }
}

/*
 *  input	根据ID，rid生成  16 uint8_t 
 *  output	用户私钥存储  128 uint8_t
 */
void sm9_key_generation(struct ecc_context ecc, uint8_t *input, size_t len, uint8_t *output)
{
    BNPoint2 deA;
    char prKey[256] = {0};
    
    sm9_key_calculate(&deA, ecc.Ke, BN.n, input, len, ecc.P2);
    P2_normorlize(&deA, deA);
    P2_toString(deA, prKey, HEX);
    convert_StrToUnChar(prKey, output, 256);
}

void sm9_key_calculate(BNPoint2 *deA, CBigInt ke, CBigInt n, uint8_t *input, size_t len, BNPoint2 P2)
{
    uint8_t *msg;
    CBigInt t1, t1_inv, t2;
    
    msg = TEE_Malloc(len+1, TEE_MALLOC_FILL_ZERO);
    TEE_MemMove(msg, input, len);
    TEE_MemFill(msg+len, 0x02, 1);
    
    Hash_1(&t1, msg, len+1, n);
    Add_Big_Big(&t1, t1, ke);
    Inv(&t1_inv, t1, n);
    Mul_Big_Big(&t2, t1_inv, ke);
    if (Cmp(t2, n) >= 0)
        Mod_Big_Big(&t2, t2, n);
    P2_multiply(deA, P2, t2);
    
    TEE_Free(msg);
}

void sm9_reset_ctx(struct sm9_context *ctx)
{
    CBigIntInit(&ctx->r);
    TEE_MemFill(ctx->IDA, 0, IDA_LEN);
    TEE_MemFill(ctx->IDB, 0, IDB_LEN);
    BNPoint_init(&ctx->RA);
    BNPoint_init(&ctx->RB);
    TEE_MemFill(ctx->SA, 0, 32);
    TEE_MemFill(ctx->SB, 0, 32);
    BNField12_init(&ctx->g1);
    BNField12_init(&ctx->g2);
    BNField12_init(&ctx->g3);
}

void sm9_set_r(struct sm9_context *ctx)
{
    uint8_t Rand[32];
    char cRand[65];
    TEE_GenerateRandom(Rand, 32);
    convert_UnCharToStr(cRand, Rand, 32);
    //Get(&ctx->r, cRand, HEX);
    Get(&ctx->r, "5879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8", HEX);
}

//output 64 uint8_t
void sm9_userA_exchangeR(struct sm9_context *ctx, struct ecc_context ecc, uint8_t *ida, uint8_t *rida, uint8_t *idb, uint8_t *ridb, uint8_t *output)
{
    TEE_MemMove(ctx->IDA, ida, ID_LEN);
    TEE_MemMove(ctx->IDA+ID_LEN, rida, RID_LEN);
    TEE_MemMove(ctx->IDB, idb, ID_LEN);
    TEE_MemMove(ctx->IDB+ID_LEN, ridb, RID_LEN);

    uint8_t msg[IDB_LEN+1];
    TEE_MemMove(msg, ctx->IDB, IDB_LEN);
    TEE_MemFill(msg+IDB_LEN, 0x02, 1);
    
    // A1-A4
    CBigInt h;
    BNPoint QB;
    Hash_1(&h, msg, IDB_LEN+1, BN.n);
    P_multiply(&QB, ecc.P1, h);
    P_add(&QB, QB, ecc.Ppube);
    P_multiply(&ctx->RA, QB, ctx->r);
    P_normorlize(&ctx->RA, ctx->RA);
    
    PtoByte(output, ctx->RA);
}

//output 64 uint8_t
void sm9_userB_exchangeR(struct sm9_context *ctx, struct ecc_context ecc, uint8_t *ida, uint8_t *rida, uint8_t *idb, uint8_t *ridb, uint8_t *output)
{
    TEE_MemMove(ctx->IDA, ida, ID_LEN);
    TEE_MemMove(ctx->IDA+ID_LEN, rida, RID_LEN);
    TEE_MemMove(ctx->IDB, idb, ID_LEN);
    TEE_MemMove(ctx->IDB+ID_LEN, ridb, RID_LEN);

    uint8_t msg[IDA_LEN+1];
    TEE_MemMove(msg, ctx->IDA, IDA_LEN);
    TEE_MemFill(msg+IDA_LEN, 0x02, 1);
    
    // B1-B4
    CBigInt h;
    BNPoint QB;
    Hash_1(&h, msg, IDA_LEN+1, BN.n);
    P_multiply(&QB, ecc.P1, h);
    P_add(&QB, QB, ecc.Ppube);
    P_multiply(&ctx->RB, QB, ctx->r);
    P_normorlize(&ctx->RB, ctx->RB);
    
    PtoByte(output, ctx->RB);
}

//output SKA 16 uint8_t
void sm9_userA_exchangeSK(struct sm9_context *ctx, struct ecc_context ecc, uint8_t *da, uint8_t *rb, uint8_t *output)
{
    uint8_t SKA[16];
    convert_unCharToBNPoint(rb, &ctx->RB);
    
    // A5 A7
    BNPoint2 da_pkey;
    convert_unCharToBNPoint2(da, &da_pkey);
    Pairing_opt(&ctx->g1, ecc.P2, ecc.Ppube);
    F12_exp(&ctx->g1, ctx->g1, ctx->r);
    Pairing_opt(&ctx->g2, da_pkey, ctx->RB);
    F12_exp(&ctx->g3, ctx->g2, ctx->r);
    
    // SKA = SKB = KDF(IDA||IDB||RA||RB||g1||g2||g3)
    int size = IDA_LEN+IDB_LEN+64+64+384+384+384;
    uint8_t R[64], G[384];
    uint8_t *msg = TEE_Malloc(size, TEE_MALLOC_FILL_ZERO);
    TEE_MemMove(msg, ctx->IDA, IDA_LEN);
    TEE_MemMove(msg+IDA_LEN, ctx->IDB, IDB_LEN);
    PtoByte(R, ctx->RA);
    TEE_MemMove(msg+IDA_LEN+IDB_LEN, R, 64);
    PtoByte(R, ctx->RB);
    TEE_MemMove(msg+IDA_LEN+IDB_LEN+64, R, 64);
    F12toByte(G, ctx->g1);
    TEE_MemMove(msg+IDA_LEN+IDB_LEN+64+64, G, 384);
    F12toByte(G, ctx->g2);
    TEE_MemMove(msg+IDA_LEN+IDB_LEN+64+64+384, G, 384);
    F12toByte(G, ctx->g3);
    TEE_MemMove(msg+IDA_LEN+IDB_LEN+64+64+384+384, G, 384);
    KDF(SKA, msg, size, 16*8);
    
    //output
    TEE_MemMove(output, SKA, 16);
}

//output SKB 16 uint8_t
void sm9_userB_exchangeSK(struct sm9_context *ctx, struct ecc_context ecc, uint8_t *db, uint8_t *ra, uint8_t *output)
{
    uint8_t SKB[16];
    convert_unCharToBNPoint(ra, &ctx->RA);
    
    // B5 B7
    BNPoint2 db_pkey;
    convert_unCharToBNPoint2(db, &db_pkey);    
    Pairing_opt(&ctx->g1, db_pkey, ctx->RA);
    Pairing_opt(&ctx->g2, ecc.P2, ecc.Ppube);
    F12_exp(&ctx->g2, ctx->g2, ctx->r);
    F12_exp(&ctx->g3, ctx->g1, ctx->r);
    
    //SKA=SKB=KDF(IDA||IDB||RA||RB||g1||g2||g3)
    int size = IDA_LEN+IDB_LEN+64+64+384+384+384;
    uint8_t R[64], G[384];
    uint8_t *msg = TEE_Malloc(size, TEE_MALLOC_FILL_ZERO);
    TEE_MemMove(msg, ctx->IDA, IDA_LEN);
    TEE_MemMove(msg+IDA_LEN, ctx->IDB, IDB_LEN);
    PtoByte(R, ctx->RA);
    TEE_MemMove(msg+IDA_LEN+IDB_LEN, R, 64);
    PtoByte(R, ctx->RB);
    TEE_MemMove(msg+IDA_LEN+IDB_LEN+64, R, 64);
    F12toByte(G, ctx->g1);
    TEE_MemMove(msg+IDA_LEN+IDB_LEN+64+64, G, 384);
    F12toByte(G, ctx->g2);
    TEE_MemMove(msg+IDA_LEN+IDB_LEN+64+64+384, G, 384);
    F12toByte(G, ctx->g3);
    TEE_MemMove(msg+IDA_LEN+IDB_LEN+64+64+384+384, G, 384);
    KDF(SKB, msg, size, 16*8);
    
    //output
    TEE_MemMove(output, SKB, 16);
}


void sm9_userA_exchangeS(struct sm9_context *ctx, uint8_t *output)
{   
    // A6
    int size = 384+384+IDA_LEN+IDB_LEN+64+64;
    uint8_t R[64], G[384];
    uint8_t *msg = TEE_Malloc(size, TEE_MALLOC_FILL_ZERO);
    F12toByte(G, ctx->g2);
    TEE_MemMove(msg, G, 384);
    F12toByte(G, ctx->g3);
    TEE_MemMove(msg+384, G, 384);
    TEE_MemMove(msg+384+384, ctx->IDA, IDA_LEN);
    TEE_MemMove(msg+384+384+IDA_LEN, ctx->IDB, IDB_LEN);
    PtoByte(R, ctx->RA);
    TEE_MemMove(msg+384+384+IDA_LEN+IDB_LEN, R, 64);
    PtoByte(R, ctx->RB);
    TEE_MemMove(msg+384+384+IDA_LEN+IDB_LEN+64, R, 64);
    
    // calculate B_X = (0x00||X)
    uint8_t out_hash[32] ,B_X[417];
    F12toByte(G, ctx->g1);
    TEE_MemMove(B_X+1, G, 384);
    sm3(msg, size, out_hash);
    TEE_MemMove(B_X+1+384, out_hash, 32);
    
    B_X[0] = 0x83;
    sm3(B_X, 417, ctx->SA);
    TEE_MemMove(output, ctx->SA, 32);
    
    B_X[0] = 0x82;
    sm3(B_X, 417, ctx->SB); 
}

void sm9_userB_exchangeS(struct sm9_context *ctx, uint8_t *output)
{
    // B6
    int size = 384+384+IDA_LEN+IDB_LEN+64+64;
    uint8_t R[64], G[384];
    uint8_t *msg = TEE_Malloc(size, TEE_MALLOC_FILL_ZERO);
    F12toByte(G, ctx->g2);
    TEE_MemMove(msg, G, 384);
    F12toByte(G, ctx->g3);
    TEE_MemMove(msg+384, G, 384);
    TEE_MemMove(msg+384+384, ctx->IDA, IDA_LEN);
    TEE_MemMove(msg+384+384+IDA_LEN, ctx->IDB, IDB_LEN);
    PtoByte(R, ctx->RA);
    TEE_MemMove(msg+384+384+IDA_LEN+IDB_LEN, R, 64);
    PtoByte(R, ctx->RB);
    TEE_MemMove(msg+384+384+IDA_LEN+IDB_LEN+64, R, 64);
    
    // calculate B_X = (0x00||X)
    uint8_t out_hash[32] ,B_X[417];
    F12toByte(G, ctx->g1);
    TEE_MemMove(B_X+1, G, 384);
    sm3(msg, size, out_hash);
    TEE_MemMove(B_X+1+384, out_hash, 32);
    
    B_X[0] = 0x83;
    sm3(B_X, 417, ctx->SA);
    
    B_X[0] = 0x82;
    sm3(B_X, 417, ctx->SB); 
    TEE_MemMove(output, ctx->SB, 32);
}

int sm9_userA_exchangeConfirm(struct sm9_context ctx, uint8_t *input)
{
    return Bytes_Equal(ctx.SB, input, 32);
}

int sm9_userB_exchangeConfirm(struct sm9_context ctx, uint8_t *input)
{
    return Bytes_Equal(ctx.SA, input, 32);
}
