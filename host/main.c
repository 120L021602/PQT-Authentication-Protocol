// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */
#include <pthread.h>
#include "socket_zmq.h"
#include "selfqueue.h"
#include <stdlib.h>
pthread_cond_t cond;
pthread_mutex_t mutex;

typedef struct identify_params
{
	Sm9_Para Sm9_Para1;
	Sm9_Key Sm9_Key1;
	ca_oppo oparams;
	ca_self sparams;
	TEEC_Context ctx_1;
	TEEC_Session sess_1;
} iden_params;

typedef struct socket_params
{
	Sm9_Para *Sm9_Para1;
	Sm9_Key *Sm9_Key1;
	ca_oppo *oparams;
	ca_self *sparams;
	TEEC_Context ctx_1;
	TEEC_Session sess_1;
} socket_params;

// node_data:
char center_ipset[] = "tcp://192.168.128.150:5555";
char node1_ipset[] = "tcp://192.168.0.150:5566"; // selfIP
char node2_ipset[] = "tcp://192.168.0.160:5566"; // for test
char node3_ipset[] = "tcp://192.168.0.153:5566";
char local_ipset[] = "tcp://*:5566";
char local_oppo_ipset[] = "tcp://localhost:5577";

char *nodeID, *nodeRID;
char *nodeIP;
// xxx1.身份认证 ; xxx2.内容认证
TEEC_UUID uuid1 = TA_LIBS_EXAMPLE_UUID;
TEEC_UUID uuid2 = TA2_LIBS_EXAMPLE_UUID;
TEEC_Context ctx1, ctx2;
TEEC_Session sess1, sess2;
TEEC_Result res;
uint32_t err_origin;
//开启TA1 TA2
void start_ta1_ta2()
{
	res = TEEC_InitializeContext(NULL, &ctx1);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	res = TEEC_OpenSession(&ctx1, &sess1, &uuid1,
						   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession unexpectedly returned with code 0x%x"
				" origin 0x%x",
			 res, err_origin);
	res = TEEC_InitializeContext(NULL, &ctx2);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	res = TEEC_OpenSession(&ctx2, &sess2, &uuid2,
						   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession unexpectedly returned with code 0x%x"
				" origin 0x%x",
			 res, err_origin);
}
//当前节点数据初始化
Sm9_Key sm9_key1;
ca_self self1;
ca_oppo oppo1;
Sm9_Para sm9_para1;
// node端服务器
void *node_server(socket_params *sock_par)
{
	zmq_Server(local_ipset, ctx1, sess1, ctx2, sess2, sock_par->oparams, sock_par->sparams, sock_par->Sm9_Para1, sock_par->Sm9_Key1);
}

void *pqc_kem_func(char *opponode_ipset)
{
	printf("\nPQC KEM START\n");
	Sm9_Key sm9_key;
	ca_self self;
	ca_oppo oppo;
	Sm9_Para sm9_para;
	int pwd = 7;
	while(pwd < 9)
	{
		char send_buffer[3296] = {0};
		int send_buffer_len = 3295;
		char rec_buffer[3296] = {0};
		pqc_node_client_send_handler(pwd, send_buffer);
		int rec_val = zmq_Client(opponode_ipset, send_buffer, send_buffer_len, rec_buffer);
		if (rec_val != 0)
		{
			continue;
		}
		node_client_receive_handler(rec_buffer, ctx1, sess1, &sm9_key, &self, &oppo, &sm9_para);
		pwd++;
	}
	if(pwd == 9){
		Sk_Secure_Read(ctx2, sess2, oppo.oppoid);
	}
	//save opponode_information
	if (hasheadnode == 0)
	{
		node_data_init(&head_node, oppo.oppoid, oppo.opporid, opponode_ipset);
		hasheadnode = 1;
	}
	else
	{
		node_data_add(&head_node, oppo.oppoid, oppo.opporid, opponode_ipset);
	}
}


// node与center交互 申请pkey
void *apply_pkey()
{
	printf("\nAPPLY_PKEY_START:\n");
	Sm9_Key sm9_key;
	ca_self self;
	ca_oppo oppo;
	Sm9_Para sm9_para;
	params_init(&oppo, &self, &sm9_para, &sm9_key, nodeID, nodeRID, nodeIP);
	printf("\nselfid:\n");
	format_print(self.selfid, 8);
	printf("\nselfrid:\n");
	format_print(self.selfrid, 8);
	int pwd = 1;
	uint8_t sk_temp_flag = 0;
	while (pwd < 3)
	{
		char send_buffer[256];
		int send_buffer_len = 257;
		char rec_buffer[1024];
		rec_buffer[0] = '0';
		printf("\npwd:%d\n", pwd);
		node_client_send_handler(pwd, send_buffer, &sm9_key, &self, &sk_temp_flag);
		int rec_val = zmq_Client(center_ipset, send_buffer, send_buffer_len, rec_buffer);
		if (rec_val != 0)
		{
			continue;
		}
		node_client_receive_handler(rec_buffer, ctx1, sess1, &sm9_key, &self, &oppo, &sm9_para);
		switch (pwd)
		{
		case 1:
			printf("\nAPPLY_PPUBE:\n");
			printf("\nppube:\n");
			format_print(sm9_key.ppube, 64);
			break;
		case 2:
			printf("\nGET_ENPKEY:\n");
			printf("\nenpkey:\n");
			format_print(sm9_key.enpkey, 128);
			break;
		default:
			break;
		}
		pwd++;
		printf("\n");
	}
	//局部变量数据转向全局存储
	memmove(sm9_key1.ppube, sm9_key.ppube, 64);
	memmove(sm9_key1.enkid, sm9_key.enkid, 112);
	memmove(sm9_key1.enpkey, sm9_key.enpkey, 128);
	//将更新rid存储进来
	memmove(self1.selfrid, self.selfrid, 8);
	memmove(sm9_para1.RIDA, sm9_para.RIDA, 8);
	printf("\nAPPLY_PKEY_END:\n");
	//获取时间戳 根据时间戳进行更新
	time_t now_time = time(NULL);
	struct tm *timeinfo;
	timeinfo = localtime(&now_time);
	past_tm cur_pt;
	time_to_ptm(timeinfo, &cur_pt);
	printf("\nPKEY_CUR_TIME:%d,%d,%d\n", cur_pt.year, cur_pt.month, cur_pt.day);
	QueuePush(&pkey_update_queue, &cur_pt, center_ipset);
	apply_key_flag = 1;
}
// node与node交互 协商sk
void *apply_sk(char *opponode_ipset)
{
	printf("\nEXCHANGE SK START:\n");
	Sm9_Key sm9_key;
	ca_self self;
	ca_oppo oppo;
	Sm9_Para sm9_para;
	//身份认证密钥数据复制到局部变量中
	params_init(&oppo, &self, &sm9_para, &sm9_key, nodeID, nodeRID, nodeIP);
	memmove(sm9_key.ppube, sm9_key1.ppube, 64);
	memmove(sm9_key.enkid, sm9_key1.enkid, 112);
	memmove(sm9_key.enpkey, sm9_key1.enpkey, 128);
	memmove(self.selfrid, self1.selfrid, 8);
	memmove(sm9_para.RIDA, sm9_para1.RIDA, 8);
	//通信阻塞位初始化
	identify_flag = 1;
	refuse_cnt = 5;
	int pwd = 3;
	uint8_t sk_temp_flag = 0;
	printf("\nselfid:\n");
	format_print(self.selfid, 8);
	printf("\nselfrid:\n");
	format_print(self.selfrid, 8);
	while (pwd < 6)
	{
		char send_buffer[256];
		int send_buffer_len = 257;
		char rec_buffer[1024];
		rec_buffer[0] = '0';
		// printf("\npwd:%d\n", pwd);

		node_client_send_handler(pwd, send_buffer, &sm9_key, &self, &sk_temp_flag);
		int rec_val = zmq_Client(opponode_ipset, send_buffer, send_buffer_len, rec_buffer);
		if (rec_val != 0)
		{
			continue;
		}
		node_client_receive_handler(rec_buffer, ctx1, sess1, &sm9_key, &self, &oppo, &sm9_para);
		//通信阻塞部分
		if (rec_buffer[0] == 'n' || rec_buffer[0] == 'k')
		{
			identify_flag = 0;
			refuse_cnt = 0;
			break;
		}
		// switch (pwd){
		// case 3:
		// 	// printf("\noopoid:\n");
		// 	// format_print(oppo.oppoid, 8);
		// 	// printf("\nopporid:\n");
		// 	// format_print(oppo.opporid, 8);
		// 	printf("\nExchange_idrid_end\n");
		// 	// printf("\nselfR:\n");
		// 	// format_print(self.selfR, 64);
		// 	break;
		// case 4:
		// 	printf("\nExchange_R_end\n");
		// 	break;
		// case 5:
		// 	printf("\nConfirm_S_end\n");
		// 	break;
		// default:
		// 	break;
		// }
		pwd++;
		if (pwd == 6)
		{
			//通信阻塞位还原
			identify_flag = 0;
			refuse_cnt = 0;
			//获取时间戳 根据时间戳进行更新
			time_t now_time = time(NULL);
			struct tm *timeinfo;
			timeinfo = localtime(&now_time);
			past_tm cur_pt;
			time_to_ptm(timeinfo, &cur_pt);
			printf("\nsk_cur_time:%d,%d,%d\n", cur_pt.year, cur_pt.month, cur_pt.day);
			QueuePush(&sk_update_queue, &cur_pt, opponode_ipset);
			// printf("\nApply sk successful!:\n");
		}
	}
	//是否需要将exchange信息存储在CA端
	// memmove(oppo1.oppoid, oppo.oppoid, 8);
	// if (hasheadnode == 0)
	// {
	// 	node_data_init(&head_node, oppo.oppoid, oppo.opporid, opponode_ipset);
	// 	hasheadnode = 1;
	// }
	// else
	// {
	// 	node_data_add(&head_node, oppo.oppoid, oppo.opporid, opponode_ipset);
	// }
	printf("\nEXCHANGE SK END!\n");
}
// node与node交互 内容认证
void *node_context(char *opponode_ipset)
{
	/// MAIN FUNC
	printf("\nNODE_CONTEXT_START:\n");
	Sm9_Key sm9_key;
	ca_self self;
	ca_oppo oppo;
	Sm9_Para sm9_para;
	//身份认证密钥数据复制到局部变量中
	params_init(&oppo, &self, &sm9_para, &sm9_key, nodeID, nodeRID, nodeIP);
	memmove(sm9_key.ppube, sm9_key1.ppube, 64);
	memmove(sm9_key.enkid, sm9_key1.enkid, 112);
	memmove(sm9_key.enpkey, sm9_key1.enpkey, 128);
	memmove(self.selfrid, self1.selfrid, 8);
	memmove(sm9_para.RIDA, sm9_para1.RIDA, 8);

	// IP+ID结构体构造
	uint8_t context_oppoid[8];
	uint8_t node_new_sk_flag = 0;
	if (!node_data_search(&head_node, opponode_ipset, context_oppoid, &node_new_sk_flag))
	{
		printf("\nNot found its ID!\n");
		return;
	}
	//memmove(oppo.oppoid, oppo1.oppoid, 8);
	int pwd = 6;

	//循环处理输入数据
	char *data[] = {"20220920200741,5.05983460316332e-05,1,1",
					"34562927200741,5.05982736454742e-05,1,1",
					"89742927200741,5.05353632634232e-05,1,1",
					"95272927200741,5.059fdsdfdfdvd2e-05,1,1"};
	struct timeval start, end;
	char send_buffer[3296] = {0};
	int send_buffer_len = 3295;
	char rec_buffer[3296] = {0};
	for (int i = 0; i < sizeof(data) / sizeof(data[0]); ++i)
	{
		//printf("\n%d, %d\n", sizeof(data), sizeof(data[0]));
		rec_buffer[0] = '0';
		self.data = data[i];
		printf("\noriginal data:");
		printf("\n%s\n", self.data);
		//gettimeofday(&start, NULL);
		Context_Hmac(ctx2, sess2, context_oppoid, self.data, self.datapackage, &node_new_sk_flag);
		// printf("\ndatapackage\n");
		// format_print(self.datapackage, 96);
		node_client_send_handler(pwd, send_buffer, &sm9_key, &self, &node_new_sk_flag);
		int rec_val = zmq_Client(opponode_ipset, send_buffer, send_buffer_len, rec_buffer);
		if (rec_val != 0)
		{
			//i--;
			printf("\nCommunication_Wrong!\n");
			continue;
		}
		node_client_receive_handler(rec_buffer, ctx2, sess2, &sm9_key, &self, &oppo, &sm9_para);

		//gettimeofday(&end, NULL);
		if(node_new_sk_flag == 1 && self.con_flag[0] == 0x01){
			node_new_sk_flag = 0;
			node_data_update_skflag(&head_node, opponode_ipset);
		}
		//long timeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
		//printf("time=%fs\n", timeuse / 1000000.0);
		//sleep(1);
	}
	printf("\nNODE_CONTEXT_END:\n");
	///
}

void *node_context_attack(char *opponode_ipset)
{
	/// MAIN FUNC
	printf("\nAttack test start:\n");
	Sm9_Key sm9_key;
	ca_self self;
	ca_oppo oppo;
	Sm9_Para sm9_para;
	//身份认证密钥数据复制到局部变量中
	params_init(&oppo, &self, &sm9_para, &sm9_key, nodeID, nodeRID, nodeIP);
	memmove(sm9_key.ppube, sm9_key1.ppube, 64);
	memmove(sm9_key.enkid, sm9_key1.enkid, 112);
	memmove(sm9_key.enpkey, sm9_key1.enpkey, 128);
	memmove(self.selfrid, self1.selfrid, 8);
	memmove(sm9_para.RIDA, sm9_para1.RIDA, 8);

	// IP+ID结构体构造
	uint8_t context_oppoid[8];
	uint8_t sk_update_flag;
	if (!node_data_search(&head_node, opponode_ipset, context_oppoid, &sk_update_flag))
	{
		printf("\nNot found its ID!\n");
		return;
	}
	// memmove(oppo.oppoid, oppo1.oppoid, 8);
	int pwd = 6;
	uint8_t lastpackage[96];
	//循环处理输入数据
	char *data[] = {"20220920200741,5.05983460316332e-05,1,1",
					"20220920200741,5.05983460316332e-05,1,1"};
	for (int i = 0; i < sizeof(data) / sizeof(data[0]); ++i)
	{
		char send_buffer[256];
		int send_buffer_len = 257;
		char rec_buffer[1024];
		rec_buffer[0] = '0';
		self.data = data[i];
		printf("\n%s\n", self.data);
		Context_Hmac(ctx2, sess2, context_oppoid, self.data, self.datapackage, 1);
		// printf("\n%d,original_datapackage:\n", i+1);
		// format_print(self.datapackage, 96);
		//篡改攻击 + 中间人攻击
		int attack_id = 0;
		if (i == 0)
		{
			printf("\nORDER:1.Tampering Attack 2.Replay Attack\n");
			scanf("%d", &attack_id);
			getchar();
			switch (attack_id)
			{
			case 1:
				printf("\n%d,original_datapackage:\n", i + 1);
				format_print(self.datapackage, 96);
				for (int j = 0; j < 2; ++j)
				{
					self.datapackage[j] = 0x10;
				}
				i += 2;
				printf("\n%d,changed_datapackage:\n", i - 1);
				format_print(self.datapackage, 96);
				break;
			case 2:
				memmove(lastpackage, self.datapackage, 96);
				break;
			default:
				break;
			}
		}
		if (i < 2)
		{
			printf("\n%d,original_datapackage:\n", i + 1);
			format_print(self.datapackage, 96);
			memmove(self.datapackage, lastpackage, 96);
			printf("\n%d,changed_datapackage\n", i + 1);
			format_print(self.datapackage, 96);
		}
		node_client_send_handler(pwd, send_buffer, &sm9_key, &self, &sk_update_flag);
		int rec_val = zmq_Client(opponode_ipset, send_buffer, send_buffer_len, rec_buffer);
		if (rec_val != 0)
		{
			i--;
			printf("\nCommunication_Wrong!\n");
			continue;
		}
		node_client_receive_handler(rec_buffer, ctx2, sess2, &sm9_key, &self, &oppo, &sm9_para);
		sleep(1);
	}
	printf("\nAttack test end!\n");
	///
}
// //计时线程 负责管理密钥更新

void *time_count_update()
{
	past_tm pkeycurdate, skcurdate;
	uint8_t rid[8];
	while (true)
	{
		if (!QueueEmpty(&pkey_update_queue))
		{
			QueueNode *curnode = QueueFront(&pkey_update_queue);
			pkeycurdate.year = curnode->cur_time.year;
			pkeycurdate.month = curnode->cur_time.month;
			pkeycurdate.day = curnode->cur_time.day;
			if (Time_Check(&pkeycurdate, 30))
			{
				// update sk
				apply_pkey();
				QueuePop(&pkey_update_queue);
			}
		}
		if (!QueueEmpty(&sk_update_queue))
		{
			QueueNode *curnode = QueueFront(&sk_update_queue);
			skcurdate.year = curnode->cur_time.year;
			skcurdate.month = curnode->cur_time.month;
			skcurdate.day = curnode->cur_time.day;
			if (Time_Check(&skcurdate, 60))
			{
				// update sk
				apply_sk(curnode->ip);
				QueuePop(&sk_update_queue);
			}
		}
		// sleep(60);
		break;
	}
}

void end_ta1_ta2()
{
	TEEC_CloseSession(&sess1);
	TEEC_FinalizeContext(&ctx1);
	TEEC_CloseSession(&sess2);
	TEEC_FinalizeContext(&ctx2);
}
/// TIME MODULE OVER


int main(int argc, char *argv[])
{
	// QueueInit(&sk_update_queue);
	// QueueInit(&pkey_update_queue);
	// if (example_heap() == OQS_SUCCESS) {
	// 	return EXIT_SUCCESS;
	// } else {
	// 	return EXIT_FAILURE;
	// }
	printf("node_start!\n");
	start_ta1_ta2();
	printf("node_end!\n");
	int ret;
	int button = 0;
	hasheadnode = 0;
	char *oppo_ipset = NULL;
	char nodeIDA[] = "Alice001";
	char nodeRIDA[] = "A1234567";
	char nodeIDB[] = "Bob00001";
	char nodeRIDB[] = "B1234567";
	char nodeIDC[] = "Cindy001";
	char nodeRIDC[] = "C1234567";
	char nodeIDD[20];
	char tempRID[8];
	// node1:
	printf("\ninput_node_information:\n");
	printf("1.node1; 2.node2; 3.node3; 0.exit;\n");
	scanf("%d", &button);
	getchar();
	switch (button)
	{
	case 1:
		oppo_ipset = node2_ipset;
		nodeIP = node1_ipset;
		// printf("\ninput the ID:\n");
		// scanf("%s", &nodeIDD);
		// getchar();
		// nodeID = nodeIDD;
		// nodeIDD[8] = '\0';
		nodeID = nodeIDA;
		nodeRID = nodeRIDA;
		break;
	case 2:
		oppo_ipset = node1_ipset;
		nodeIP = node2_ipset;
		nodeID = nodeIDB;
		nodeRID = nodeRIDB;
		break;
	case 3:
		oppo_ipset = node1_ipset;
		nodeIP = node3_ipset;
		nodeID = nodeIDC;
		nodeRID = nodeRIDC;
		break;
	default:
		break;
	}
	printf("\n%s\n", nodeID);
	memmove(Ca_Self_ID, nodeID, 8);
	printf("\n%s\n", Ca_Self_ID);
	pthread_t pqc_kem;
	
	params_init(&oppo1, &self1, &sm9_para1, &sm9_key1, nodeID, nodeRID, nodeIP);
	//params_init(&oppo2, &self2, &sm9_para2, &sm9_key1, nodeID, nodeRID, nodeIP);
	pthread_t apply_pk, node_ser;
	pthread_t ex_sk1, ex_sk2;
	pthread_t node_con1, node_con2;
	pthread_t time_update;
	pthread_t attack_test;
	socket_params sock_par;
	sock_par.oparams = &oppo1;
	sock_par.sparams = &self1;
	sock_par.Sm9_Key1 = &sm9_key1;
	sock_par.Sm9_Para1 = &sm9_para1;
	res = sig_keypair_invoke(ctx1, sess1, Ca_Self_Sig_Pk);
	//节点开server
	ret = pthread_create(&node_ser, NULL, node_server, &sock_par);
	if (ret != 0)
	{
		printf("Create pthread error!\n");
		return 1;
	}

	while (1)
	{
		printf("********************************************\n");
		printf("\nNode Function:\n");
		printf("1.pqc_kem; 2.exchange_sk; 3.node_context; \n4.time_update; 5.attack_test; 6.exchange_sk_wrong; \n0.exit\n");
		printf("********************************************\n");
		printf("please input your order:");
		char c[10] = {0};
		gets(c);
		switch (c[0])
		{
		case '1': //pqc authen kem
			ret = pthread_create(&pqc_kem, NULL, pqc_kem_func, oppo_ipset);
			if (ret != 0)
			{
				printf("Create apply_pkey_pthread error!\n");
				return 1;
			}
			pthread_join(pqc_kem, NULL);
			break;
		case '2': //身份认证交换sk
			if (!apply_key_flag)
			{
				printf("Please apply key first\n");
				break;
			}
			ret = pthread_create(&ex_sk1, NULL, apply_sk, oppo_ipset);
			if (ret != 0)
			{
				printf("Create exchange_sk_pthread error!\n");
				return 1;
			}
			pthread_join(ex_sk1, NULL);
			break;
		case '3': //内容认证
			// if (!apply_key_flag)
			// {
			// 	printf("Please apply key first\n");
			// 	break;
			// }
			ret = pthread_create(&node_con1, NULL, node_context, oppo_ipset);
			if (ret != 0)
			{
				printf("Create node_context_pthread error!\n");
				return 1;
			}
			pthread_join(node_con1, NULL);
			break;
		case '4': // update
			ret = pthread_create(&time_update, NULL, time_count_update, NULL);
			if (ret != 0)
			{
				printf("Create node_context_pthread error!\n");
				return 1;
			}

			break;
		case '5': // attack_test
			ret = pthread_create(&attack_test, NULL, node_context_attack, oppo_ipset);
			if (ret != 0)
			{
				printf("Create node_context_pthread error!\n");
				return 1;
			}
			pthread_join(attack_test, NULL);
			break;
		case '6':
			printf("\norignal rid:");
			format_print(self1.selfrid, 8);
			for (int i = 0; i < 1; i++)
			{
				tempRID[i] = self1.selfrid[i];
				self1.selfrid[i] = '2';
				sm9_para1.RIDA[i] = '2';
			}
			printf("\nchanged rid:");
			format_print(self1.selfrid, 8);
			ret = pthread_create(&ex_sk2, NULL, apply_sk, oppo_ipset);
			if (ret != 0)
			{
				printf("Create exchange_sk_pthread error!\n");
				return 1;
			}
			pthread_join(ex_sk1, NULL);
			for (int i = 0; i < 1; i++)
			{
				self1.selfrid[i] = tempRID[i];
				sm9_para1.RIDA[i] = tempRID[i];
			}
			break;
		case '0':
			exit(0);
			break;
		default:
			break;
		}
	}
	pthread_join(node_ser, NULL);
	pthread_join(time_update, NULL);
	end_ta1_ta2();
}
