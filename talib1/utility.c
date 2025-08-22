//
// Created by xy on 11/8/2021
//

#include "utility.h"
#include "libmath.h"

//对两个字节数组进行异或运算
void Bytes_XOR(BYTE *b, BYTE *b1, BYTE *b2, int len)
{
    int i;
    for(i=0;i<len;i++)
        b[i] = b1[i]^b2[i];
}

//判断两个字节数组是否相等
int Bytes_Equal(BYTE *b1, BYTE *b2, int len)
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

//打印显示Byte数组
void printByte(BYTE* b,int len)
{
    int i;
    for(i = 0;i<len;i++)
        printf("%02X",b[i]);
}

//将16进制字符串转换为BYTE数组，注意length需要为偶数，转换后msg的长度为lenth/2
void HextoByte(BYTE *msg, BYTE *hex, int length)
{
    int len,i,j,k;
    len = length/2;
    for (i = 0; i < len; i++)
    {
        j = 2*i;
        if((hex[j]>='0')&&(hex[j]<='9'))
            msg[i] = hex[j]-48;
        else if((hex[j]>='A')&&(hex[j]<='F'))
            msg[i]=hex[j]-55;
        else if((hex[j]>='a')&&(hex[j]<='f'))
            msg[i] = hex[j]-87;
        else
            msg[i] = 0;
        msg[i]*= 16;
        k = j + 1;
        if((hex[k]>='0')&&(hex[k]<='9'))
            msg[i] += (hex[k]-48);
        else if((hex[k]>='A')&&(hex[k]<='F'))
            msg[i] += (hex[k]-55);
        else if((hex[k]>='a')&&(hex[k]<='f'))
            msg[i] += (hex[k]-87);

    }
}

//将unsigned int转为BYTE数组,hash长度固定为8位
void DwordtoByte(BYTE *out_hash, DWORD *hash)
{
	int i = 0;
	for (i = 0; i < 8; i++)
	{
		out_hash[i*4] = (hash[i] >> 24) & 0xFF;
		out_hash[i*4+1] = (hash[i] >> 16) & 0xFF;
		out_hash[i*4+2] = (hash[i] >> 8) & 0xFF;
		out_hash[i*4+3] = (hash[i]) & 0xFF;
	}
}

void BytetoDwordbyte(BYTE *hash, BYTE *out_hash)
{
    int i = 0;
    for(i = 0; i < 8; i++)
    {
        out_hash[4*i] = hash[4*i+3];
        out_hash[4*i+1] = hash[4*i+2];
        out_hash[4*i+2] = hash[4*i+1];
        out_hash[4*i+3] = hash[4*i];
    }
}


//把12次扩域元素转换为BYTE数组，得到大小为384字节大小的msg
void F12toByte(BYTE *msg, BNField12 b)
{
    BYTE *str;
    str = PutFieldElement(b.sq.im.im,HEX);
    HextoByte(msg, str, 64);
    str = PutFieldElement(b.sq.im.re,HEX);
    HextoByte(&msg[32], str, 64);
    str = PutFieldElement(b.sq.re.im,HEX);
    HextoByte(&msg[64], str, 64);
    str = PutFieldElement(b.sq.re.re,HEX);
    HextoByte(&msg[96], str, 64);
    str = PutFieldElement(b.im.im.im,HEX);
    HextoByte(&msg[128], str, 64);
    str = PutFieldElement(b.im.im.re,HEX);
    HextoByte(&msg[160], str, 64);
    str = PutFieldElement(b.im.re.im,HEX);
    HextoByte(&msg[192], str, 64);
    str = PutFieldElement(b.im.re.re,HEX);
    HextoByte(&msg[224], str, 64);
    str = PutFieldElement(b.re.im.im,HEX);
    HextoByte(&msg[256], str, 64);
    str = PutFieldElement(b.re.im.re,HEX);
    HextoByte(&msg[288], (BYTE*)str, 64);
    str = PutFieldElement(b.re.re.im,HEX);
    HextoByte(&msg[320], str, 64);
    str = PutFieldElement(b.re.re.re,HEX);
    HextoByte(&msg[352], str, 64);
}

//将点P转换为64个字节串，注意P需为规范型
void PtoByte(BYTE *b, BNPoint P)
{
    BYTE *str;
    str = PutFieldElement(P.x,HEX);
    HextoByte(b, str, 64);
    str = PutFieldElement(P.y,HEX);
    HextoByte(&b[32], str, 64);
}


/*
  k：生成的共享密钥
  msg:输入消息的字节指针
  msglen:输入消息的字节长度
  klen : 需要获取的共享密钥的比特长度
*/
void KDF(BYTE *k, BYTE *msg, int msgLength, int klen)
{
    int ct,v,len2,i,n,m,cur;
    BYTE *Msg2,hash_byte[32];
    ct = 1;              //初始化计算器为1
    v = 256;             //SM3输出长度为256位
    len2 = msgLength + 4;   //  哈希函数H = Hv(Z||ct)
    
    Msg2 = TEE_Malloc((uint32_t)len2, TEE_MALLOC_FILL_ZERO);
    
    for(i=0;i<msgLength;i++)
        Msg2[i] = msg[i];
    n = Ceil((double)klen/v);
    m = klen - v*Floor((double)klen/v);
    
    cur = 0;
    for(i=1;i<n;i++)
    {
        Msg2[len2-1] = ct;
        sm3(Msg2,len2,hash_byte);
        TEE_MemMove(&k[cur],hash_byte,32);
        ct++;
        cur += 32;
    }
    
    Msg2[len2-1] = ct;
    sm3(Msg2,len2,hash_byte);
    if(klen%v == 0)
        TEE_MemMove(&k[cur],hash_byte,32);
    else
        TEE_MemMove(&k[cur],hash_byte,m/8);

    TEE_Free(Msg2);
}

/*
  h1：函数返回值
  msg:输入消息的字节指针
  len:输入消息的字节长度
  n : 通常为大整数N
*/
void Hash_1(CBigInt *h1, BYTE *msg, int len, CBigInt n)
{
    int i,len2;
    BYTE *msg2,hash_byte[32],out[32];
    DWORD Ha[10];
    CBigInt HA,Mod;
    len2 = len + 1 + 4;   //  H = Hv(0x01||Z||ct)
    msg2 = TEE_Malloc((uint32_t)len2, TEE_MALLOC_FILL_ZERO);
    msg2[0] = 0x01;
    TEE_MemMove(&msg2[1],msg,len);

    if(Cmp(n,BN.n)== 0)  //Hash_1的输入参数n通常为N，即群的阶数
    {
        msg2[len2-1] = 0x01;      //memcpy(&msg2[len2-4],&ct,4);
        sm3(msg2, len2, hash_byte);
        BytetoDwordbyte(hash_byte, out);
        TEE_MemMove(Ha,out,32);
        msg2[len2-1] = 0x02;      //memcpy(&msg2[len2-4],&ct,4);
        sm3(msg2, len2, hash_byte);
        BytetoDwordbyte(hash_byte, out);
        TEE_MemMove(&Ha[8],out,8);

        HA.m_nLength = 10;
        for(i = 0; i<10; i++)          // 将Ha数据类型转换为整数
            HA.m_ulValue[i] = Ha[9-i];
        i = HA.m_nLength-1;
        while(HA.m_ulValue[i]==0 && i>0)
        {
            HA.m_nLength--;
            i--;
        }
        Sub_Big_Long(&Mod,BN.n,1);
        Mod_Big_Big(h1,HA,Mod);
        Add_Big_Long(h1,*h1,1);

    } else {
        printf(" Hash1中存在未处理的异常！ \n");
    }

    TEE_Free(msg2);
}

/*
 *  unsigned char to char
 */
void convert_UnCharToStr(char* str, unsigned char* unChar, int ucLen)
{
    const char hex_char[] = "0123456789ABCDEF";
    int i;
    unsigned int x;
    for(i = 0; i < ucLen; i++)
    {
       x = (unChar[i] & 0xf0) >> 4;
       str[2*i] = hex_char[x];
       x = (unChar[i] & 0x0f);
       str[2*i+1] = hex_char[x];
    }
}

/*
 *  char to unsigned char
 */
void convert_StrToUnChar(char* str, unsigned char* unChar, int cLen)
{
    int i, j;
    unsigned char x[2];
    for(i = 0; i < cLen; i+=2)
    {
        for(j=i;j<i+2;j++)
        {
            if(str[j] >= 'A' && str[j] < 'a')
            {
                x[j-i] = str[j] - 'A' + 10;
            } else if(str[j] >= 'a') {
                x[j-i] = str[j] - 'a' + 10;
            } else {
                x[j-i] = str[j] - '0';
            }
        }
        unChar[i/2] = (x[0] << 4) | x[1];
    }
}

/*
 *  uint8_t 转 BNPoint
 */
void convert_unCharToBNPoint(uint8_t *c, BNPoint *R)
{
    char str[65] = {0};
    convert_UnCharToStr(str, c, 32);
    Get(&R->x, str, HEX);

    convert_UnCharToStr(str, c+32, 32);
    Get(&R->y, str, HEX);

    // add a R.z init, this code only run as a example
    Mov_Big_Long(&R->z, 1);
}

/*
 *  uint8_t 转 BNPoint2
 */
void convert_unCharToBNPoint2(uint8_t *c, BNPoint2 *R)
{
    char str[65] = {0};
    convert_UnCharToStr(str, c, 32);
    Get(&R->x.im, str, HEX);

    convert_UnCharToStr(str, c+32, 32);
    Get(&R->x.re, str, HEX);

    convert_UnCharToStr(str, c+64, 32);
    Get(&R->y.im, str, HEX);

    convert_UnCharToStr(str, c+96, 32);
    Get(&R->y.re, str, HEX);

    // add a R.z init, this code only run as a example
    F2_construct(&R->z, BN.ONE, BN.ZERO);
}


