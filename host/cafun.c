#include "cafun.h"

#define DATAPACKAGESIZE 96
#define DATASIZE 68

uint8_t identify_flag;
uint8_t refuse_cnt;
uint8_t hasheadnode;
node_data head_node;

uint8_t apply_key_flag;

uint8_t Ca_Self_ID[8];
uint8_t Ca_Self_Sig_Pk[SIG_PK_LEN];
uint8_t Ca_Sig_Msg[KEM_PK_LEN + SIGNATURE_LEN];

void time_to_rid(uint8_t* RIDA, struct tm* timeinfo){
	int year_end = timeinfo->tm_year+1900, month_end = timeinfo->tm_mon+1, day_end = timeinfo->tm_mday;
	int a = year_end/100, b = year_end -a*100; 
	RIDA[0] = (uint8_t)a, RIDA[1] = (uint8_t)b;
	RIDA[2] = (uint8_t)month_end, RIDA[3] = (uint8_t)day_end;
	for(int i = 4;i<8;i++){
		RIDA[i] = (uint8_t)rand()%255;
	}
}

void time_to_ptm(struct tm* timeinfo, past_tm* pt)
{
	int year_end = timeinfo->tm_year+1900;
	int month_end = timeinfo->tm_mon+1;
	int day_end = timeinfo->tm_mday;
	pt->year = year_end;
	pt->month = month_end;
	pt->day = day_end;
}

void params_init(ca_oppo *oparams, ca_self *sparams, Sm9_Para *sm9_str, Sm9_Key *sm9_key, char* IDA, char* RIDA, char* IPA)
{
	// uint8_t IDA[] = { 0x01,0x23,0x45,0x67,0x76,0x54,0x32,0x10 };
	// uint8_t RIDA[] = { 0x20,0x21,0x12,0x16,0x01,0x23,0x45,0x67};
	//// USE TIME TO GET RID
	//uint8_t RIDA[8] = {0};
	time_t raw_time = time(NULL);
    struct tm *timeinfo;
	timeinfo = localtime (&raw_time);
	//uint8_t RIDA[8] = {0};
	time_to_rid(RIDA, timeinfo);
	// for(int i=0;i<8;i++){
	// 	printf("%02x\n", RIDA[i]);
	// }
	// char IDA[] = "Alice001";
	// char RIDA[] = "A1234567";
	//char RIDA[] = "A1234567";

	/// RECEIVE IDB RIDB FROM NODE_B
	//char IDB[] = "Bob00001";
	//char RIDB[] = "B1234567";
	memmove(sparams->selfid, IDA, 8);
	memmove(sparams->selfrid, RIDA, 8);
	memmove(sparams->selfip, IPA, 26);
	memmove(sm9_str->IDA, IDA, 8);
	memmove(sm9_str->RIDA, RIDA, 8);
	//memmove(oparams->oppoid, IDB, 8);
	//memmove(oparams->opporid, RIDB, 8);
	//memmove(sm9_str->IDB, IDB, 8);
	//memmove(sm9_str->RIDB, RIDB, 8);
	//uint8_t ppube[64] = {0x91,0x74,0x54,0x26 ,0x68,0xE8,0xF1,0x4A,0xB2,0x73,0xC0,0x94 ,0x5C,0x36,0x90,0xC6 ,0x6E,0x5D,0xD0,0x96 ,0x78,0xB8,0x6F,0x73 ,0x4C,0x43,0x50,0x56 ,0x7E,0xD0,0x62,0x83
//,0x54,0xE5,0x98,0xC6 ,0xBF,0x74,0x9A,0x3D ,0xAC,0xC9,0xFF,0xFE ,0xDD,0x9D,0xB6,0x86 ,0x6C,0x50,0x45,0x7C ,0xFC,0x7A,0xA2,0xA4 ,0xAD,0x65,0xC3,0x16 ,0x8F,0xF7,0x42,0x10};
	uint8_t ppube[64] = {0};
	uint8_t enkid[112] = {0};
	uint8_t enpkey[128] = {0}; 
	uint8_t datapackage[96] = {0};
	uint8_t con_f[4] = {0};
	memmove(sm9_key->ppube, ppube, 64);
	memmove(sm9_key->enkid, enkid, 112);
	memmove(sm9_key->enpkey, enpkey, 128);
	memmove(sparams->datapackage, datapackage, 96);
	memmove(sparams->con_flag, con_f, 4);
	sparams->data = NULL;
	//printf("init_successful!\n");
}

void params_update(ca_oppo *oparams, ca_self *sparams, Sm9_Para *sm9_str, Sm9_Key *sm9_key)
{
	// uint8_t IDA[] = { 0x01,0x23,0x45,0x67,0x76,0x54,0x32,0x10 };
	// uint8_t RIDA[] = { 0x20,0x21,0x12,0x16,0x01,0x23,0x45,0x67};
	//char IDA[] = "Alice001";
	//char RIDA[] = "A1234567";
	//char IDB[] = "Bob00001";
	char RIDB[] = "B1234567";
	uint8_t RIDA[8] = {0};
	time_t raw_time = time(NULL);
    struct tm *timeinfo;
	timeinfo = localtime (&raw_time);
	time_to_rid(RIDA, timeinfo);
	for(int i=0;i<8;i++){
		printf("%02x\n", RIDA[i]);
	}
	//// GET RIDB FROM NODE_B 
	memmove(sparams->selfrid, RIDA, 8);
	memmove(sm9_str->RIDA, RIDA, 8);
	memmove(oparams->opporid, RIDB, 8);
	memmove(sm9_str->RIDB, RIDB, 8);
	uint8_t enkid[112] = {0};
	memmove(sm9_key->enkid, enkid, 112);
	printf("update_successful!\n");
}

TEEC_Result Identify_Depkey_R(TEEC_Context ctx, TEEC_Session sess, Sm9_Para *sm9_str, Sm9_Key *sm9_key)
{
	TEEC_Result res1;
	TEEC_Operation op;
	uint32_t origin;
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_MEMREF_TEMP_OUTPUT);
		//TEEC_NONE);
	op.params[0].tmpref.buffer = sm9_str;
	op.params[0].tmpref.size = 32;
	op.params[1].tmpref.buffer = sm9_key->enpkey;
	op.params[1].tmpref.size = 128;
	op.params[2].tmpref.buffer = sm9_str->RA;
	op.params[2].tmpref.size = 64;
	op.params[3].tmpref.buffer = sm9_str->RB;
	op.params[3].tmpref.size = 64;
	res1 = TEEC_InvokeCommand(&sess,
		TA_IDENTIFY_DEPKEY_R,
		&op, &origin);
	return res1;
}

TEEC_Result Identify_Depkey(TEEC_Context ctx, TEEC_Session sess, Sm9_Key *sm9_key)
{
	TEEC_Result res1;
	TEEC_Operation op;
	uint32_t origin;
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
		TEEC_NONE,
		TEEC_NONE,
		TEEC_NONE);
		//TEEC_NONE);
	op.params[0].tmpref.buffer = sm9_key->enpkey;
	op.params[0].tmpref.size = 128;
	res1 = TEEC_InvokeCommand(&sess,
		TA_IDENTIFY_DEPKEY,
		&op, &origin);
	return res1;
}

TEEC_Result Identify_Confirm_S(TEEC_Context ctx, TEEC_Session sess, ca_oppo *oppo, int pwd)
{
	printf("\nConfirm sk start:\n");
	TEEC_Result res1;
	TEEC_Operation op;
	uint32_t origin;
	uint8_t flag[4] = {0x00, 0x00, 0x00, 0x00};
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_NONE);
	op.params[0].tmpref.buffer = oppo->oppoS;
	op.params[0].tmpref.size = 32;
	op.params[1].tmpref.buffer = flag;
	op.params[1].tmpref.size = 4;


	uint8_t c_or_s_flag[4] = {0x00, 0x00, 0x00, 0x00};
	if(pwd){
		c_or_s_flag[0] = 0x01;
	}
	op.params[2].tmpref.buffer = c_or_s_flag;
	op.params[2].tmpref.size = 4;
	res1 = TEEC_InvokeCommand(&sess,
		TA_IDENTIFY_CONFIRM_S,
	&op, &origin);
	if(flag[0] == 0x01){
		printf("\nConfirm sk successful!\n");
		if (hasheadnode == 0)
		{
			node_data_init(&head_node, oppo->oppoid, oppo->opporid, oppo->oppoip);
			hasheadnode = 1;
		}
		else
		{
			node_data_add(&head_node, oppo->oppoid, oppo->opporid, oppo->oppoip);
		}
	}else{
		printf("\nConfirm sk defeated!\n");
	}
	return res1;
}
//pwd:
TEEC_Result Identify_ExchangeR(TEEC_Context ctx, TEEC_Session sess, Sm9_Para *sm9_str, int pwd)
{
	//printf("\nexchangeR start!\n");
	printf("\nExchange R start:\n");
	TEEC_Result res1;
	TEEC_Operation op;
	uint32_t origin;
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_NONE);
		//TEEC_NONE);
	op.params[0].tmpref.buffer = sm9_str;
	op.params[0].tmpref.size = 32;
	op.params[1].tmpref.buffer = sm9_str->RA;
	op.params[1].tmpref.size = 64;
	uint8_t c_or_s_flag[4] = {0x00, 0x00, 0x00, 0x00};
	if(pwd){
		c_or_s_flag[0] = 0x01;
	}
	op.params[2].tmpref.buffer = c_or_s_flag;
	op.params[2].tmpref.size = 4;
	res1 = TEEC_InvokeCommand(&sess,
		TA_IDENTIFY_EXCHANGER,
		&op, &origin);
	//printf("\nexchangeR successful!\n");
	printf("\nExchange R successful!\n");
	return res1;
}
//caculate the sk
TEEC_Result Identify_Gensk_S(TEEC_Context ctx, TEEC_Session sess, Sm9_Para *sm9_str, Sm9_Key *sm9_key, int pwd)
{
	printf("\nGenerate sk start:\n");
	TEEC_Result res1;
	TEEC_Operation op;
	uint32_t origin;
	memset(&op, 0, sizeof(op));
	//input:R from another node ; output: S to confirm key 
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_NONE
		//TEEC_MEMREF_TEMP_OUTPUT,
		//TEEC_MEMREF_TEMP_INPUT
		);
	op.params[0].tmpref.buffer = sm9_str->RB;
	op.params[0].tmpref.size = 64;
	op.params[1].tmpref.buffer = sm9_str->SA;
	op.params[1].tmpref.size = 32;

	
	uint8_t c_or_s_flag[4] = {0x00, 0x00, 0x00, 0x00};
	if(pwd){
		c_or_s_flag[0] = 0x01;
	}
	op.params[2].tmpref.buffer = c_or_s_flag;
	op.params[2].tmpref.size = 4;
	res1 = TEEC_InvokeCommand(&sess,
		TA_IDENTIFY_GENSK_S,
		&op, &origin);
	printf("\nGenerate sk successful!\n");
	return res1;
}

//CACULATE THE ENKID
TEEC_Result Identify_Enkid(TEEC_Context ctx, TEEC_Session sess,  Sm9_Key *sm9_key)
{
	TEEC_Result res1;
	TEEC_Operation op;
	uint32_t origin;
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_NONE,
		TEEC_NONE);
	//uint8_t enpkey[112] ={0} ;
	op.params[0].tmpref.buffer = sm9_key;
	op.params[0].tmpref.size = 64;
	op.params[1].tmpref.buffer = sm9_key->enkid;
	op.params[1].tmpref.size = 112;
	res1 = TEEC_InvokeCommand(&sess,
		TA_IDENTIFY_ENKID,
		&op, &origin);
	return res1;
}

//context_hmac(TA2)
TEEC_Result Context_Hmac(TEEC_Context ctx, TEEC_Session sess,  char* oppoid, char* data, uint8_t* datapackage, uint8_t* sk_flag)
{
	TEEC_Result res1;
	TEEC_Operation op;
	uint32_t origin;
	uint8_t output[96]={0};
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INPUT);
	size_t data_len = strlen(data);
	//uint8_t enpkey[112] ={0} ;
	op.params[0].tmpref.buffer = data;
	op.params[0].tmpref.size = data_len;
	op.params[1].tmpref.buffer = output;
	op.params[1].tmpref.size = 96;
	op.params[2].tmpref.buffer = oppoid;
	op.params[2].tmpref.size = 8;
	op.params[3].tmpref.buffer = sk_flag;
	op.params[3].tmpref.size = 1;
	res1 = TEEC_InvokeCommand(&sess,
		TA2_CONTEXT_HMAC,
		&op, &origin);
	// printf("output:\n");
	// format_print(output, 96);
	memmove(datapackage, output, 96);
	return res1;
}

TEEC_Result Context_DeHmac(TEEC_Context ctx, TEEC_Session sess, char* oppoid, uint8_t* datapackage, char* data, uint8_t* sk_flag)
{
	TEEC_Result res1;
	TEEC_Operation op;
	uint32_t origin;
	uint8_t dedata[72] = {0};
	dedata[0] = 0x00;
	dedata[1] = 0x00;
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INPUT);
	op.params[0].tmpref.buffer = datapackage;
	op.params[0].tmpref.size = DATAPACKAGESIZE;
	op.params[1].tmpref.buffer = dedata;
	op.params[1].tmpref.size = 72;
	op.params[2].tmpref.buffer = oppoid;
	op.params[2].tmpref.size = 8;
	op.params[3].tmpref.buffer = sk_flag;
	op.params[3].tmpref.size = 1;
	res1 = TEEC_InvokeCommand(&sess,
		TA2_CONTEXT_DEHMAC,
		&op, &origin);
	memmove(data, dedata, 72);
}
//无论返回怎样结果都需要进行更新（需要回收msg结构体，pwd=1代表更新 pwd=0代表不更新）
TEEC_Result Context_Update(TEEC_Context ctx, TEEC_Session sess, uint8_t pwd){
	TEEC_Result res1;
	TEEC_Operation op;
	uint32_t origin;
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
		TEEC_NONE,
		TEEC_NONE,
		TEEC_NONE);
	uint8_t pos[] = {0x00, 0x00, 0x00, 0x00};
	if(pwd){
		pos[0] = 0x01;
	}
	op.params[0].tmpref.buffer = pos;
	op.params[0].tmpref.size = 4;
	//printf("\nupdate_test1\n");
	res1 = TEEC_InvokeCommand(&sess,
		TA2_CONTEXT_UPDATE,
		&op, &origin);

	//printf("\nupdate_test2\n");
}
//Time update module
void init_time(past_tm *ptm){
	ptm->year = 0;
	ptm->month = 0;
	ptm->day = 0;
}

bool Time_Check(past_tm *ptm ,int k) {
    time_t raw_time = time(NULL);
    struct tm *timeinfo;
	timeinfo = localtime (&raw_time);
	printf("%d\n",timeinfo->tm_mon);
	printf("%s\n",timeinfo->tm_zone);
	if(ptm->year == 0){
		ptm->year = timeinfo->tm_year+1900;
		ptm->month = timeinfo->tm_mon+1;
		ptm->day = timeinfo->tm_mday;
		return true;
	}
    int year_end = timeinfo->tm_year+1900, month_end = timeinfo->tm_mon+1, day_end = timeinfo->tm_mday;
	int year_start = ptm->year,month_start = ptm->month, day_start = ptm->day;
	int y2, m2, d2;
	int y1, m1, d1;
	m1 = (month_start + 9) % 12;
	y1 = year_start - m1/10;
	d1 = 365*y1 + y1/4 - y1/100 + y1/400 + (m1*306 + 5)/10 + (day_start - 1);
	m2 = (month_end + 9) % 12;
	y2 = year_end - m2/10;
	d2 = 365*y2 + y2/4 - y2/100 + y2/400 + (m2*306 + 5)/10 + (day_end - 1);
	int equal = d2-d1;
	if(equal >= k){
		ptm->year = year_end, ptm->month = month_end, ptm->day = day_end;
		return true;
	}
	return true;
}

void rid_to_time(uint8_t* rid, past_tm* pt)
{
	pt->year = ((int)rid[0])*100+(int)rid[1];
	pt->month = (int)rid[2];
	pt->day = (int)rid[3];
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

void node_data_init(node_data *head, uint8_t *id, uint8_t *rid, char *ip)
{
	//printf("\nnode_init!\n");
	head->next = NULL;
	head->new_sk_flag = 1;
	memmove(head->nodeID, id, 8);
	memmove(head->nodeRID, rid, 8);
	memmove(head->nodeIP, ip, 26);
}
int Str_Equal(char *b1, char *b2, int len)
{
    int i=0;
    while(i<len)
    {
        if(b1[i]!=b2[i])
            return 0;
        i++;
    }
    return 1;
}
void node_data_add(node_data *head, uint8_t *id, uint8_t *rid, char *ip)
{
	//printf("\nnode_add!\n");
	node_data *node = head;
	node_data *prev = NULL;
	while(node != NULL){
        if(Str_Equal(node->nodeIP, ip, 26)){
            node->new_sk_flag = 1;
            break;
        }
        prev = node;
        node = node->next;
    }
	if(node == NULL)
    {
        node = (node_data *)malloc(sizeof(node_data));
        memmove(node->nodeID, id, 8);
		memmove(node->nodeRID, rid, 8);
		memmove(node->nodeIP, ip, 26);
        node->next = NULL;
		node->new_sk_flag = 1;
        prev->next = node;
    }
}
// 1.found  0.not_found
int node_data_search(node_data *head,  char* ip, uint8_t* out_id, uint8_t* sk_flag)
{
	node_data *node = head;
	node_data *prev = NULL;
	while(node != NULL){
        if(Str_Equal(node->nodeIP, ip, 26)){
            memmove(out_id, node->nodeID, 8);
			*sk_flag = node->new_sk_flag; 
            return 1;
        }
        prev = node;
        node = node->next;
    }
	if(node == NULL)
	{
		printf("\nNot_found!\n");
		return 0;
	}
}

void node_data_update_skflag(node_data *head, char *ip){
	node_data *node = head;
	node_data *prev = NULL;
	while(node != NULL){
        if(Str_Equal(node->nodeIP, ip, 26)){
            node->new_sk_flag = 0;
            return 1;
        }
        prev = node;
        node = node->next;
    }
	return 1;
}

TEEC_Result Sk_Secure_Read(TEEC_Context ctx, TEEC_Session sess, char* oppoid)
{
	TEEC_Result res1;
	TEEC_Operation op;
	uint32_t origin;
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
		TEEC_NONE,
		TEEC_NONE,
		TEEC_NONE);
	op.params[0].tmpref.buffer = oppoid;
	op.params[0].tmpref.size = 8;
	res1 = TEEC_InvokeCommand(&sess,
		TA2_SECURE_READ,
		&op, &origin);
	return res1;
}


TEEC_Result save_opposigpk_invoke(TEEC_Context ctx, TEEC_Session sess, uint8_t* oppo_id, uint8_t* oppo_sig_pk)
{
	//printf("\nexchangeR start!\n");
	printf("\nSave opposigpk invoke\n");
	TEEC_Result res1;
	TEEC_Operation op;
	uint32_t origin;
	struct timeval start, end;
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_NONE,
		TEEC_NONE);
	op.params[0].tmpref.buffer = oppo_id;
	op.params[0].tmpref.size = 8;
	op.params[1].tmpref.buffer = oppo_sig_pk;
	op.params[1].tmpref.size = SIG_PK_LEN;
	gettimeofday(&start, NULL);
	res1 = TEEC_InvokeCommand(&sess,
		TA_SAVE_OPPOSIGPK,
		&op, &origin);
	//printf("\nexchangeR successful!\n");
	gettimeofday(&end, NULL);
	long timeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
	printf("\nSave opposigpk time=%fs\n", timeuse / 1000000.0);
	printf("\nSave opposigpk successful!\n");
	return res1;
}

TEEC_Result sig_keypair_invoke(TEEC_Context ctx, TEEC_Session sess, uint8_t* self_sig_pk)
{
	//printf("\nexchangeR start!\n");
	printf("\nSig keypair invoke\n");
	TEEC_Result res1;
	TEEC_Operation op;
	uint32_t origin;
	struct timeval start, end;
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_NONE,
		TEEC_NONE,
		TEEC_NONE);
	op.params[0].tmpref.buffer = self_sig_pk;
	op.params[0].tmpref.size = SIG_PK_LEN;
	gettimeofday(&start, NULL);
	res1 = TEEC_InvokeCommand(&sess,
		TA_SIG_KEYPAIR,
		&op, &origin);
	//printf("\nexchangeR successful!\n");
	gettimeofday(&end, NULL);
	long timeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
	printf("\nSig keypair time=%fs\n", timeuse / 1000000.0);
	printf("\nSig keypair successful!\n");
	return res1;
}

TEEC_Result kem_keypair_invoke(TEEC_Context ctx, TEEC_Session sess, uint8_t* sig_msg)
{
	//printf("\nexchangeR start!\n");
	printf("\nKem keypair invoke\n");
	TEEC_Result res1;
	TEEC_Operation op;
	uint32_t origin;
	struct timeval start, end;
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_NONE,
		TEEC_NONE,
		TEEC_NONE);
	op.params[0].tmpref.buffer = sig_msg;
	op.params[0].tmpref.size = KEM_PK_LEN + SIGNATURE_LEN;
	gettimeofday(&start, NULL);
	res1 = TEEC_InvokeCommand(&sess,
		TA_KEM_KEYPAIR,
		&op, &origin);
	//printf("\nexchangeR successful!\n");
	gettimeofday(&end, NULL);
	long timeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
	printf("\nKem keypair time=%fs\n", timeuse / 1000000.0);
	printf("\nKem keypair successful!\n");
	return res1;
}

TEEC_Result authen_encape_invoke(TEEC_Context ctx, TEEC_Session sess, uint8_t* oppo_id, uint8_t* sig_msg, uint8_t* sig_ct)
{
	//printf("\nexchangeR start!\n");
	printf("\nAuthen encape invoke\n");
	TEEC_Result res1;
	TEEC_Operation op;
	uint32_t origin;
	struct timeval start, end;
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_NONE);
	op.params[0].tmpref.buffer = sig_msg;
	op.params[0].tmpref.size = KEM_PK_LEN + SIGNATURE_LEN;
	op.params[1].tmpref.buffer = oppo_id;
	op.params[1].tmpref.size = 8;
	op.params[2].tmpref.buffer = sig_ct;
	op.params[2].tmpref.size = CT_LEN + SIGNATURE_LEN;
	gettimeofday(&start, NULL);
	res1 = TEEC_InvokeCommand(&sess,
		TA_AUTHEN_ENCAPE,
		&op, &origin);
	gettimeofday(&end, NULL);
	long timeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
	printf("\nAuthen encape time=%fs\n", timeuse / 1000000.0);
	printf("\nAuthen encape successful!\n");
	return res1;
}

TEEC_Result authen_decape_invoke(TEEC_Context ctx, TEEC_Session sess, uint8_t* oppo_id, uint8_t* sig_ct)
{
	//printf("\nexchangeR start!\n");
	printf("\nAuthen decape invoke\n");
	TEEC_Result res1;
	TEEC_Operation op;
	uint32_t origin;
	struct timeval start, end;
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_NONE,
		TEEC_NONE);
	op.params[0].tmpref.buffer = sig_ct;
	op.params[0].tmpref.size = CT_LEN + SIGNATURE_LEN;
	op.params[1].tmpref.buffer = oppo_id;
	op.params[1].tmpref.size = 8;
	gettimeofday(&start, NULL);
	res1 = TEEC_InvokeCommand(&sess,
		TA_AUTHEN_DECAPE,
		&op, &origin);
	gettimeofday(&end, NULL);
	long timeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
	printf("\nAuthen decape time=%fs\n", timeuse / 1000000.0);
	//printf("\nexchangeR successful!\n");
	printf("\nAuthen decape successful!\n");
	return res1;
}

