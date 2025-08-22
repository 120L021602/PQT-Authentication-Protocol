// 
// created by liu on 12/15/2021
//

#ifndef PKEY_H
#define PKEY_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include "utility.h"

//Center nodelist
typedef struct Cnode
{
    unsigned char id[8];
    unsigned char rid[8];
    unsigned char kid[16];
    unsigned char pkey[128];
    struct Cnode *next;
}Cnode;

typedef struct Nnode
{
	uint8_t id[8];
	uint8_t rid[8];
	uint8_t kid[16];
	uint8_t pkey[128];
    uint8_t sk[16];
    int flag;
}Nnode;

extern Nnode node1;
extern Cnode head1,tail1;
extern Nnode opponodes[5];
//通信的完整结构体
void Nnode_init(Nnode *opponode, int len);
int Nnode_search(Nnode *opponode, int len, uint8_t* cur_id);
void Nnode_update(Nnode *opponode, int len, uint8_t* cur_id, uint8_t* cur_rid, uint8_t* cur_sk);


void Cnode_init(Cnode *head, Cnode *tail,uint8_t *id, uint8_t *rid, uint8_t *kid, uint8_t *pkey); 

void Cnode_insert(Cnode *head, Cnode *tail, uint8_t *id, uint8_t *rid, uint8_t *kid, uint8_t *pkey);

void Cnode_sort(Cnode *head, Cnode *tail, uint8_t *id, uint8_t *rid, uint8_t *kid, uint8_t *pkey);

void Cnode_update(bool flag, uint8_t* cur_rid, uint8_t* new_rid);
//code
void cau_depkey(uint8_t* kid, uint8_t* enpkey, uint8_t* depkey);
//center
void cau_enpkey(uint8_t* kid, uint8_t* pkey, uint8_t* enpkey);

void format_print(uint8_t* arg, size_t len);
#endif /* PKEY_H */