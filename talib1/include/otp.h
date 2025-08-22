#ifndef OTP_H
#define OTP_H

#include "sm3.h"
#include "utility.h"
#include "mtwister.h"

#ifndef otp_context

#define HMAC_DATA_LEN 128
#define MSG_DATA_CUTPOS 18
#define MSG_DATA_CUTLEN 13

struct msg_context {
    char Msg[64];	//only used 39
    size_t MLen;
    uint8_t Hmac[32];
};

typedef struct otp_context {
    uint8_t id[8];
    uint8_t rid[8];
    uint8_t IDrid[16];
    uint8_t SK[16];
    struct msg_context LastContext;
    uint8_t Seed[4];
    uint8_t Counts;
}otp_context;
#endif
extern otp_context *otp_cons[5]; 
extern otp_context *otp_c, *server_otp_c;
extern struct msg_context *temp_msg_c;
extern uint8_t first_sk_package[32];

void otp_cons_init(otp_context **oppo_otp, int len);

int otp_cons_search(otp_context **oppo_otp, int len, uint8_t* cur_id);

void msg_context_init(struct msg_context *msg_ctx, char *str, size_t len);

void msg_context_move(struct msg_context *msg_ctx, struct msg_context msg_ctx_new);

void msg_context_free(struct msg_context *msg_ctx);

void otp_context_init(struct otp_context *otp_ctx, uint8_t *id, uint8_t *rid, uint8_t *sk, uint8_t *seed, size_t i);

void otp_context_hmac(struct otp_context *otp_ctx, struct msg_context *msg_ctx, uint8_t *output);

int otp_context_equal(struct otp_context *otp_ctx, struct msg_context *msg_ctx);

int otp_context_update(struct otp_context *otp_ctx, struct msg_context msg_ctx);

#endif /* OTP_H */
