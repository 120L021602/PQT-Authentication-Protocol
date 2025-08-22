#ifndef CAFUN_H
#define CAFUN_H
#include <stdio.h>
#include <tee_client_api.h>
#include <libs_ta.h>
#include <libs_ta2.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>
#include <err.h>
#include <stdint.h>
#include <talib2.h>
#include <oqs/oqs.h>
//#include "socket_zmq.h"
//#include "log.h"


//dlithium2 and kyber512 size
#define SIG_PK_LEN 1312
#define SIG_SK_LEN 2528
#define KEM_PK_LEN 800
#define KEM_SK_LEN 1632
#define SIGNATURE_LEN 2420
#define CT_LEN 768

typedef struct node_data
{
	uint8_t nodeID[8];
	uint8_t nodeRID[8];
	char nodeIP[27];
	uint8_t new_sk_flag;
	struct node_data *next;
}node_data;


extern node_data head_node;
extern uint8_t identify_flag;
extern uint8_t refuse_cnt;
extern uint8_t hasheadnode;
extern uint8_t apply_key_flag;


extern uint8_t Ca_Self_ID[8];
extern uint8_t Ca_Self_Sig_Pk[SIG_PK_LEN];
extern uint8_t Ca_Sig_Msg[KEM_PK_LEN + SIGNATURE_LEN];

typedef struct SM9_STR
{
	uint8_t IDA[8];//self
	uint8_t RIDA[8];//self
	uint8_t IDB[8];//get
	uint8_t RIDB[8];
	uint8_t RA[64];//self
	uint8_t RB[64];//get
	uint8_t SA[32];//self 
	uint8_t SB[32];//get
}Sm9_Para;

typedef struct SM9_KEY
{
	uint8_t ppube[64];
	/// need to be changed
	uint8_t enkid[112];
	uint8_t enpkey[128];
}Sm9_Key;

//struct for communicationg
typedef struct node_ca_oppoparams
{
	uint8_t oppoip[32];
	uint8_t oppoid[8];
	uint8_t opporid[8];
	uint8_t oppoR[64];
	uint8_t oppoS[32];
}ca_oppo;

typedef struct node_ca_selfparams
{
	uint8_t selfip[32];
	uint8_t selfid[8];
	uint8_t selfrid[8];
	uint8_t selfR[64];
	uint8_t selfS[32];
	uint8_t datapackage[96];
	uint8_t con_flag[4];
	char *data;
}ca_self;

typedef struct center_ca_params
{	//get from node
	uint8_t nodeID[8];
	uint8_t nodeRID[8];
	uint8_t enkid[112];
	//send to node
	uint8_t enpkey[128];
}center_ca_params;

typedef struct past_time
{
	int year;
	int month;
	int day;
}past_tm;


void node_data_init(node_data *head, uint8_t *id, uint8_t *rid, char *ip);

void node_data_add(node_data *head, uint8_t *id, uint8_t *rid, char* ip);
// 1.found  0.not_found
int node_data_search(node_data *head,  char* ip, uint8_t* out_id, uint8_t* sk_flag);

void node_data_update_skflag(node_data *head, char *ip);

void time_to_rid(uint8_t* RIDA, struct tm* timeinfo);
void time_to_ptm(struct tm* timeinfo, past_tm* pt);
void rid_to_time(uint8_t* rid, past_tm* pt);

void params_init(ca_oppo *oparams, ca_self *sparams, Sm9_Para *sm9_str, Sm9_Key *sm9_key, char *IDA, char *RIDA, char *IPA);
void params_update(ca_oppo *oparams, ca_self *sparams, Sm9_Para *sm9_str, Sm9_Key *sm9_key);
TEEC_Result Identify_Depkey_R(TEEC_Context ctx, TEEC_Session sess, Sm9_Para *sm9_str, Sm9_Key *sm9_key);
TEEC_Result Identify_Depkey(TEEC_Context ctx, TEEC_Session sess, Sm9_Key *sm9_key);
TEEC_Result Identify_ExchangeR(TEEC_Context ctx, TEEC_Session sess, Sm9_Para *sm9_str, int pwd);
TEEC_Result Identify_Gensk_S(TEEC_Context ctx, TEEC_Session sess, Sm9_Para *sm9_str, Sm9_Key *sm9_key, int pwd);
TEEC_Result Identify_Enkid(TEEC_Context ctx, TEEC_Session sess,  Sm9_Key *sm9_key);
TEEC_Result Context_Hmac(TEEC_Context ctx, TEEC_Session sess,  char* oppoid, char* data, uint8_t* datapackage, uint8_t* sk_flag);
TEEC_Result Context_DeHmac(TEEC_Context ctx, TEEC_Session sess, char* oppoid, uint8_t* datapackage, char* data, uint8_t* sk_flag);
TEEC_Result Context_Update(TEEC_Context ctx, TEEC_Session sess, uint8_t pwd);
TEEC_Result Identify_Confirm_S(TEEC_Context ctx, TEEC_Session sess, ca_oppo *oppo, int pwd);
void init_time(past_tm *ptm);
bool Time_Check(past_tm *ptm ,int k);
void format_print(uint8_t* arg, size_t len);
int Str_Equal(char *b1, char *b2, int len);

TEEC_Result Sk_Secure_Read(TEEC_Context ctx, TEEC_Session sess, char* oppoid);

TEEC_Result save_opposigpk_invoke(TEEC_Context ctx, TEEC_Session sess, uint8_t* oppo_id, uint8_t* oppo_sig_pk);

TEEC_Result sig_keypair_invoke(TEEC_Context ctx, TEEC_Session sess, uint8_t* self_sig_pk);

TEEC_Result kem_keypair_invoke(TEEC_Context ctx, TEEC_Session sess, uint8_t* sig_msg);

TEEC_Result authen_encape_invoke(TEEC_Context ctx, TEEC_Session sess, uint8_t* oppo_id, uint8_t* sig_msg, uint8_t* sig_ct);

TEEC_Result authen_decape_invoke(TEEC_Context ctx, TEEC_Session sess, uint8_t* oppo_id, uint8_t* sig_ct);

#endif 