// 
// created by liu on 12/15/2021
//

#include "pkey.h"
#include <stdio.h>
#include <tee_internal_api.h>
#include "sm4.h"

Nnode node1;
Cnode head1,tail1;
Nnode opponodes[5];
// all below func  belong to center
//first save nodepkey
void Cnode_init(Cnode *head, Cnode *tail,uint8_t *id, uint8_t *rid, uint8_t *kid, uint8_t *pkey)
{
    head = (Cnode *)TEE_Malloc(sizeof(Cnode),0);
    head->next = NULL;
    tail = head;
    TEE_MemMove(head->id,id,8);
    printf("\n");
    for(int i=0;i<8;i++){
        printf("%02X ",head->id[i]);
    }
    printf("\n");
    TEE_MemMove(head->rid,rid,8);
    for(int i=0;i<8;i++){
        printf("%02X ",head->rid[i]);
    }
    printf("\n");
    TEE_MemMove(head->kid,kid,16);
    for(int i=0;i<16;i++){
        printf("%02X ",head->kid[i]);
    }
    printf("\n");
    TEE_MemMove(head->pkey,pkey,128);
       for(int i=0;i<128;i++){
        printf("%02X ",head->pkey[i]);
    }
    printf("\n");
}
//insert new nodedata 
void Cnode_insert(Cnode *head, Cnode *tail, uint8_t *id, uint8_t *rid, uint8_t *kid, uint8_t *pkey)
{
    Cnode *p;
    p = (Cnode *)TEE_Malloc(sizeof(Cnode),0);
    TEE_MemMove(p->id,id,8);
    TEE_MemMove(p->rid,rid,8);
    TEE_MemMove(p->kid,kid,16);
    TEE_MemMove(p->pkey,pkey,128);
    tail->next = p;
    tail = p;
}
//decide whether need to be updated or not 
void Cnode_update(bool flag,uint8_t* cur_rid, uint8_t* new_rid)
{
        uint8_t cur_time[4],new_time[4];
        TEE_MemMove(cur_time, cur_rid, 4);
        TEE_MemMove(new_time, new_rid, 4);
        /// convert uin8_t to int need to be writed
        int year_start,month_start,day_start;
        int year_end,month_end,day_end;
        int y2, m2, d2;
        int y1, m1, d1;
        m1 = (month_start + 9) % 12;
        y1 = year_start - m1/10;
        d1 = 365*y1 + y1/4 - y1/100 + y1/400 + (m1*306 + 5)/10 + (day_start - 1);
        m2 = (month_end + 9) % 12;
        y2 = year_end - m2/10;
        d2 = 365*y2 + y2/4 - y2/100 + y2/400 + (m2*306 + 5)/10 + (day_end - 1);
        int equal = d2-d1;
        if(equal>=30) 
            flag = true;
}
//sort whether need to be updated or inserted or not
void Cnode_sort(Cnode *head, Cnode *tail, uint8_t *id, uint8_t *rid, uint8_t *kid, uint8_t *pkey)
{
    Cnode *p = head;
    bool flag_insert = true,flag_update = false;
    while(p!=NULL){
        if(!Bytes_Equal(id, p->id, 8))
            p = p->next;
        else{
            flag_insert = false;
            // void update func(whether or not)
            Cnode_update(flag_update,p->rid,rid);
            if(flag_update){
                TEE_MemMove(p->rid,rid,4);
                TEE_MemMove(p->kid,kid,16);
                TEE_MemMove(p->pkey,pkey,128);
            }
            break;
        }
    }
    if(flag_insert)
        Cnode_insert(head,tail,id,rid,kid,pkey);
}

void Nnode_init(Nnode *opponode, int len)
{
    for(int i=0;i<len;++i){
        memset(opponode[i].id, 0, 8);
        memset(opponode[i].rid, 0, 8);
        memset(opponode[i].kid, 0, 16);
        memset(opponode[i].sk, 0, 16);
        opponode[i].flag = 0;
    }
}
int Nnode_search(Nnode *opponode, int len, uint8_t* cur_id){
    int i=0;
    for(; i<len; ++i){
        if(!(opponode[i].flag))break;
        if(Bytes_Equal(cur_id, opponode[i].id, 8)){
            return i;
        }
    }
    return i;
}

void Nnode_update(Nnode *opponode, int len, uint8_t* cur_id, uint8_t* cur_rid, uint8_t* cur_sk){
    int unused_node = Nnode_search(opponode, len, cur_id);
    Nnode *cur_opponode = &opponode[unused_node];
    memmove(cur_opponode->id, cur_id, 8);
    memmove(cur_opponode->rid, cur_rid, 8);
    memmove(cur_opponode->sk, cur_sk, 8);
    cur_opponode->flag = 1;
}
//code
void cau_enpkey(uint8_t* kid, uint8_t* pkey, uint8_t* enpkey)
{
    sm4_ecb_encryption(pkey, 128, kid, enpkey);
}
//center
void cau_depkey(uint8_t* kid, uint8_t* enpkey, uint8_t* depkey)
{
    sm4_ecb_decryption(enpkey, 16, kid, depkey);
}

void format_print(uint8_t* arg, size_t len)
{
	size_t k = len/8;
	for(int i=0;i<k;i++){
		for(int j=0;j<8;j++){
			printf("%02X  ",arg[j+i*8]);	
		}
		printf("\n");
	}	
}