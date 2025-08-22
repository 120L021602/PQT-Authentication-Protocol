
#ifndef SM9_H
#define SM9_H

#include "utility.h"

#ifndef ecc_context
#define NO_KE_MODE 0
#define WITH_KE_MODE 1

#define ID_LEN 8
#define RID_LEN 8 // 4 uint8_t time + 4 uint8_t rand
#define IDA_LEN 16
#define IDB_LEN 16

struct ecc_context {
	CBigInt Ke;
	BNPoint P1;
	BNPoint Ppube;
	BNPoint2 P2;
};
#endif


#ifndef sm9_context
struct sm9_context {
	CBigInt r;
	uint8_t IDA[IDA_LEN], IDB[IDB_LEN];
	BNPoint RA, RB;
	uint8_t SA[32], SB[32];
	BNField12 g1, g2, g3;
};
extern struct sm9_context sm9_n;
extern struct ecc_context ecc_n;
#endif

void sm9_set_para(struct ecc_context *ecc, int mode, uint8_t *input);

void sm9_key_generation(struct ecc_context ecc, uint8_t *input, size_t len, uint8_t *output);

void sm9_key_calculate(BNPoint2* deA, CBigInt ke, CBigInt n, uint8_t *input, size_t len, BNPoint2 P2);

void sm9_reset_ctx(struct sm9_context *ctx);

void sm9_set_r(struct sm9_context *ctx);

void sm9_userA_exchangeR(struct sm9_context *ctx, struct ecc_context ecc, uint8_t *ida, uint8_t *rida, uint8_t *idb, uint8_t *ridb, uint8_t *output);

void sm9_userB_exchangeR(struct sm9_context *ctx, struct ecc_context ecc, uint8_t *ida, uint8_t *rida, uint8_t *idb, uint8_t *ridb, uint8_t *output);

void sm9_userA_exchangeSK(struct sm9_context *ctx, struct ecc_context ecc, uint8_t *da, uint8_t *rb, uint8_t *output);

void sm9_userB_exchangeSK(struct sm9_context *ctx, struct ecc_context ecc, uint8_t *db, uint8_t *ra, uint8_t *output);

void sm9_userA_exchangeS(struct sm9_context *ctx, uint8_t *output);

void sm9_userB_exchangeS(struct sm9_context *ctx, uint8_t *output);

int sm9_userA_exchangeConfirm(struct sm9_context ctx, uint8_t *input);

int sm9_userB_exchangeConfirm(struct sm9_context ctx, uint8_t *input);

#endif /* SM9_H */
