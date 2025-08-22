#include "socket_handle.h"

void node_client_send_handler(int a, char *send_buffer, Sm9_Key *sm9_key, ca_self *self, uint8_t *sk_flag) // TO BE COMPELETED
{
    char prehead[] = "00";
    switch (a)
    {
    case 1:
        prehead[0] = '1';
        memmove(send_buffer, prehead, 1);
        break;
    case 2:
        prehead[0] = '2';
        memmove(send_buffer, prehead, 1);
        memmove(send_buffer + 1, self->selfid, 8);
        memmove(send_buffer + 1 + 8, self->selfrid, 8);
        memmove(send_buffer + 1 + 8 + 8, sm9_key->enkid, 112);
        break;
    case 3:
        prehead[0] = '3';
        memmove(send_buffer, prehead, 1);
        memmove(send_buffer + 1, self->selfid, 8);
        memmove(send_buffer + 1 + 8, self->selfrid, 8);
        memmove(send_buffer + 1 + 8 + 8, self->selfip, 26);
        break;
    case 4:
        prehead[0] = '4';
        memmove(send_buffer, prehead, 1);
        memmove(send_buffer + 1, self->selfR, 64);
        break;
    case 5:
        prehead[0] = '5';
        memmove(send_buffer, prehead, 1);
        memmove(send_buffer + 1, self->selfS, 32);
        break;
    case 6:
        prehead[0] = '6';
        memmove(send_buffer, prehead, 1);
        memmove(send_buffer + 1, self->datapackage, 96);
        memmove(send_buffer + 1 + 96, self->selfid, 8);
        memmove(send_buffer + 1 + 96 + 8, sk_flag, 1);
        break;
    case -1:
        memmove(send_buffer, 'k', 1);
        break;
    default:
        break;
    }
}

void node_client_receive_handler(char *node_client_rec_buffer, TEEC_Context ctx, TEEC_Session sess, Sm9_Key *sm9_key, ca_self *self, ca_oppo *oppo, Sm9_Para *sm9_para)
{
    TEEC_Result res;
    // int is_error = zmq_Receive(socket, node_client_rec_buffer);
    switch (node_client_rec_buffer[0])
    {
    case '1': // receive ppube ; ppube crypy kid; sent enkid (to center);
        memmove(sm9_key->ppube, node_client_rec_buffer + 1, 64);
        res = Identify_Enkid(ctx, sess, sm9_key);
        break;
    case '2': // receive enpkey ; kid encrypy pkey;
        memmove(sm9_key->enpkey, node_client_rec_buffer + 1, 128);
        res = Identify_Depkey(ctx, sess, sm9_key);
        break;
    case '3': // receive oppoid, rid;
        memmove(oppo->oppoid, node_client_rec_buffer + 1, 8);
        memmove(oppo->opporid, node_client_rec_buffer + 1 + 8, 8);
        memmove(oppo->oppoip, node_client_rec_buffer + 1 + 8 + 8, 26);
        memmove(sm9_para->IDB, oppo->oppoid, 8);
        memmove(sm9_para->RIDB, oppo->opporid, 8);
        res = Identify_ExchangeR(ctx, sess, sm9_para, 1);
        memmove(self->selfR, sm9_para->RA, 64);
        // printf("\nselfR:\n");
        // format_print(self->selfR, 64);
        break;
    case '4': // receive oppoR;
        memmove(oppo->oppoR, node_client_rec_buffer + 1, 64);
        memmove(sm9_para->RB, oppo->oppoR, 64);
        res = Identify_Gensk_S(ctx, sess, sm9_para, sm9_key, 1);
        memmove(self->selfS, sm9_para->SA, 32);
        break;
    case '5':
        memmove(oppo->oppoS, node_client_rec_buffer + 1, 32);
        memmove(sm9_para->SB, oppo->oppoS, 32);
        res = Identify_Confirm_S(ctx, sess, oppo, 1);
        break;
    case '6':
        memmove(self->con_flag, node_client_rec_buffer + 1, 1);
        if (self->con_flag[0] == 0x01)
        {
            printf("\ncontext identify successful!\n");
            res = Context_Update(ctx, sess, 1);
        }
        else
        {
            printf("\ncontext identify defeat!\n");
            res = Context_Update(ctx, sess, 0);
        }
        break;

    case '7':
    {
        uint8_t case7_oppo_sig_pk[SIG_PK_LEN];
        uint8_t case7_oppo_id[8];
        memmove(case7_oppo_sig_pk, node_client_rec_buffer + 1, SIG_PK_LEN);
        memmove(case7_oppo_id, node_client_rec_buffer + 1 + SIG_PK_LEN, 8);

        res = save_opposigpk_invoke(ctx, sess, case7_oppo_id, case7_oppo_sig_pk);

        res = kem_keypair_invoke(ctx, sess, Ca_Sig_Msg);
        break;
    }
    case '8':
    {
        uint8_t case8_sig_ct[CT_LEN + SIGNATURE_LEN];
        uint8_t case8_oppo_id[8];
        memmove(case8_sig_ct, node_client_rec_buffer+1, CT_LEN + SIGNATURE_LEN);
        memmove(case8_oppo_id, node_client_rec_buffer + 1 + CT_LEN + SIGNATURE_LEN, 8);
        memmove(oppo->oppoid, node_client_rec_buffer + 1 + CT_LEN + SIGNATURE_LEN, 8);
        res = authen_decape_invoke(ctx, sess, case8_oppo_id, case8_sig_ct);
        break;
    }
    case 'n':
        printf("\nOpponode_is_identifing, please wait!\n");
        wait(10000);
        break;
    case 'k':
        printf("\nThis ID is unregistered!\n");
        break;
    default:
        break;
    }
}

void node_server_receive_handler(TEEC_Context ctx, TEEC_Session sess, TEEC_Context ctx2, TEEC_Session sess2,
                                 char *node_server_rec_buffer, char *send_buffer, int send_bufferLen, ca_oppo *oparams,
                                 ca_self *sparams, Sm9_Para *sm9_para, Sm9_Key *sm9_key)
{
    // void *socket;
    TEEC_Result res;
    // char *node_server_rec_buffer;
    char prehead[] = "00";
    // if (apply_key_flag == 0)
    // {
    //     prehead[0] = 'k';
    //     memmove(send_buffer, prehead, 1);
    //     // printf("Memmove finish\n");
    // }
    // else
    // {
        switch (node_server_rec_buffer[0])
        {
        case '3': // receive oppoid, rid; send selfid,rid;
            if (identify_flag == 1)
            {
                if (refuse_cnt > 0)
                {
                    refuse_cnt--;
                    prehead[0] = 'n';
                    memmove(send_buffer, prehead, 1);
                    break;
                }
            }
            prehead[0] = '3';
            memmove(oparams->oppoid, node_server_rec_buffer + 1, 8);
            memmove(oparams->opporid, node_server_rec_buffer + 1 + 8, 8);
            memmove(oparams->oppoip, node_server_rec_buffer + 1 + 8 + 8, 26);
            //数据存到结构体中
            if (hasheadnode == 0)
            {
                node_data_init(&head_node, oparams->oppoid, oparams->opporid, oparams->oppoip);
                hasheadnode = 1;
            }
            else
            {
                node_data_add(&head_node, oparams->oppoid, oparams->opporid, oparams->oppoip);
            }
            memmove(sm9_para->IDB, oparams->oppoid, 8);
            memmove(sm9_para->RIDB, oparams->opporid, 8);
            memmove(send_buffer, prehead, 1);
            memmove(send_buffer + 1, sparams->selfid, 8);
            memmove(send_buffer + 1 + 8, sparams->selfrid, 8);
            memmove(send_buffer + 1 + 8 + 8, sparams->selfip, 26);
            identify_flag = 1;
            refuse_cnt = 5;
            break;
        case '4': // receive oppo_R, send self_R;
            prehead[0] = '4';
            memmove(oparams->oppoR, node_server_rec_buffer + 1, 64);
            memmove(sm9_para->RB, oparams->oppoR, 64);
            res = Identify_ExchangeR(ctx, sess, sm9_para, 0);
            memmove(sparams->selfR, sm9_para->RA, 64);
            memmove(send_buffer, prehead, 1);
            memmove(send_buffer + 1, sparams->selfR, 64);
            break;
        case '5':
            prehead[0] = '5';
            memmove(oparams->oppoS, node_server_rec_buffer + 1, 32);
            memmove(sm9_para->SB, oparams->oppoS, 32);
            res = Identify_Gensk_S(ctx, sess, sm9_para, sm9_key, 0);
            memmove(sparams->selfS, sm9_para->SA, 32);
            memmove(send_buffer, prehead, 1);
            memmove(send_buffer + 1, sparams->selfS, 32);
            // printf("\nsend_buffer_success! \n");
            res = Identify_Confirm_S(ctx, sess, oparams, 0);
            identify_flag = 0;
            break;
        case '6':
            prehead[0] = '6';
            uint8_t con_oppo_id[8];
            uint8_t sk_update_flag = 0;
            uint8_t package[96];
            char rec_data[72];
            memmove(package, node_server_rec_buffer + 1, 96);
            memmove(con_oppo_id, node_server_rec_buffer + 1 + 96, 8);
            memmove(&sk_update_flag, node_server_rec_buffer + 1 + 96 + 8, 1);
            res = Context_DeHmac(ctx2, sess2, con_oppo_id, package, rec_data, &sk_update_flag);
            //此处可以判断成功或失败，是否要给时频设备回传data
            //需要给client回传内容认证结果 0x01为成功 0x00为失败
            memmove(send_buffer, prehead, 1);
            memmove(send_buffer + 1, rec_data, 1);
            if (rec_data[0] == 0x01)
            {
                //将data存储或回传给时频设备;
                char buff[128] = {0};
                int ten = rec_data[1] - '0';
                int one = rec_data[2] - '0';
                int len = ten * 10 + one;
                //printf("\n%d\n", len);
                for (int i = 3; i < 3 + len; ++i)
                {
                    buff[i - 3] = rec_data[i];
                }
                buff[len] = '\0';
                printf("\ndedata:\n", buff);
                printf("%s\n", buff);
            }
            else
            {
                printf("\nnode_context_server_defeat!\n");
                // char buff[128];
                // int ten = rec_data[1] - '0';
                // int one = rec_data[2] - '0';
                // int len = ten*10+one;
                // for(int i=3; i<3+len; ++i){
                //     buff[i-3] = rec_data[i];
                // }
                // buff[len] = '\0';
                // printf("\ndata:\n", buff);
                // printf("%s\n", buff);
            }
            break;
        case '7':
        {
            prehead[0] = '7';
            uint8_t case7_oppo_sig_pk[SIG_PK_LEN];
            uint8_t case7_oppo_id[8];
            memmove(case7_oppo_sig_pk, node_server_rec_buffer + 1, SIG_PK_LEN);
            memmove(case7_oppo_id, node_server_rec_buffer + 1 + SIG_PK_LEN, 8);
            
            res = save_opposigpk_invoke(ctx, sess, case7_oppo_id, case7_oppo_sig_pk);
            
            memmove(send_buffer, prehead, 1);
            memmove(send_buffer + 1, Ca_Self_Sig_Pk, SIG_PK_LEN);
            memmove(send_buffer + 1 + SIG_PK_LEN, Ca_Self_ID, 8);
            break;
        }
        case '8':
        {
            prehead[0] = '8';
            uint8_t case8_sig_msg[KEM_PK_LEN + SIGNATURE_LEN];
            uint8_t case8_sig_ct[CT_LEN + SIGNATURE_LEN];
            uint8_t case8_oppo_id[8];
            memmove(case8_sig_msg, node_server_rec_buffer+1, KEM_PK_LEN + SIGNATURE_LEN);
            memmove(case8_oppo_id, node_server_rec_buffer+1+KEM_PK_LEN + SIGNATURE_LEN, 8);
            
            res = authen_encape_invoke(ctx, sess, case8_oppo_id, case8_sig_msg, case8_sig_ct);
            res = Sk_Secure_Read(ctx2, sess2, case8_oppo_id);
            memmove(send_buffer, prehead, 1);
            memmove(send_buffer+1, case8_sig_ct, CT_LEN + SIGNATURE_LEN);
            memmove(send_buffer+1+CT_LEN+SIGNATURE_LEN, Ca_Self_ID, 8);
            break;
        }
        default:
            break;
        }
    //}
}


void pqc_node_client_send_handler(int a, char *send_buffer)
{
    char prehead[] = "00";
    switch (a)
    {
    case 7:
        prehead[0] = '7';
        memmove(send_buffer, prehead, 1);
        memmove(send_buffer + 1, Ca_Self_Sig_Pk, SIG_PK_LEN);
        memmove(send_buffer + 1 + SIG_PK_LEN, Ca_Self_ID, 8);
        //printf("case7_send_sf.");
        //format_print(send_buffer, 32);
        break;
    case 8:
        prehead[0] = '8';
        memmove(send_buffer, prehead, 1);
        memmove(send_buffer + 1, Ca_Sig_Msg, KEM_PK_LEN + SIGNATURE_LEN);
        memmove(send_buffer + 1 + KEM_PK_LEN + SIGNATURE_LEN, Ca_Self_ID, 8);
        //printf("case8_send_sf.");
        //format_print(send_buffer, 32);
        break;
    default:
        break;
    }
}




