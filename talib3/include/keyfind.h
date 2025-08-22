#ifndef KEY_FIND_H
#define KEY_FIND_H

#include "params.h"
#include <stdint.h>

typedef struct sig_pk_data
{
	uint8_t oppo_id[8];
	uint8_t oppo_sig_pk[CRYPTO_PUBLICKEYBYTES_SIG];
	struct sig_pk_data *next;

}sig_pk_data;

extern sig_pk_data sig_node_head;

int ID_Equal(uint8_t* b1, uint8_t* b2, int len);

void sig_data_insert(sig_pk_data *head, uint8_t *id, uint8_t* pk);

int sig_data_search(sig_pk_data *head, uint8_t *id, uint8_t* pk);

#endif