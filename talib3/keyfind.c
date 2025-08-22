#include "keyfind.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


sig_pk_data sig_node_head;

int ID_Equal(uint8_t* b1, uint8_t* b2, int len){
    int i=0;
    while(i<len)
    {
        if(b1[i] != b2[i])
            return 0;
        i++;
    }
    return 1;
}

//pk is input
void sig_data_insert(sig_pk_data *head, uint8_t *id, uint8_t* pk)
{
    sig_pk_data *node = head;
    sig_pk_data *prev = NULL;
    while(node != NULL){
        if(ID_Equal(node->oppo_id, id, 8)){
            memmove(node->oppo_sig_pk, pk, CRYPTO_PUBLICKEYBYTES_SIG);
            break;
        }
        prev = node;
        node = node->next;
    }
    if(node == NULL)
    {
        node = (sig_pk_data *)malloc(sizeof(sig_pk_data));
        memmove(node->oppo_id, id, 8);
        memmove(node->oppo_sig_pk, pk, CRYPTO_PUBLICKEYBYTES_SIG);
        node->next = NULL;
        if(prev)
            prev->next = node;
    }
}

// pk is output  1.found  0.not_found
int sig_data_search(sig_pk_data *head, uint8_t *id, uint8_t* pk)
{
    sig_pk_data *node = head;
    sig_pk_data *prev = NULL;
    while(node != NULL){
        if(ID_Equal(node->oppo_id, id, 8)){
            memmove(pk, node->oppo_sig_pk, CRYPTO_PUBLICKEYBYTES_SIG);
            return 0;
        }
        prev = node;
        node = node->next;
    }
    printf("\nNot_found!\n");
    return -1;
}