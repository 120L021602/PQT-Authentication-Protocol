
#ifndef SM2_H
#define SM2_H

#include "sm9.h"

struct sm2_context {
    uint8_t str[16];
    int strLen;
    uint8_t str_en[112];
    int enLen;
};

void sm2_set_str(struct sm2_context *ctx, uint8_t *input);

void sm2_set_stren(struct sm2_context *ctx, uint8_t *input);

int sm2_encryption(struct sm2_context *ctx, struct ecc_context ecc);

int sm2_decryption(struct sm2_context *ctx, struct ecc_context ecc);

int sm2_en(struct ecc_context ecc, uint8_t *input, uint8_t *output);

int sm2_de(struct ecc_context ecc, uint8_t *input, uint8_t *output);

#endif /* SM2_H */
