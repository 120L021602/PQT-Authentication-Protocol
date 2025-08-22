#include <stdint.h>
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
}ca_self;

typedef struct  center_ca_params
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