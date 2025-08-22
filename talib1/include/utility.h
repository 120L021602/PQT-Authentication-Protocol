// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */
#ifndef UTILITY_H
#define UTILITY_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "bn_pairing.h"
#include "sm3.h"

#ifndef DWORD
typedef unsigned int DWORD;
#endif

#ifndef BYTE
typedef unsigned char BYTE;
#endif

//对两个字节数组进行异或运算
void Bytes_XOR(BYTE *b, BYTE *b1, BYTE *b2, int len);

//判断两个字节数组是否相等
int Bytes_Equal(BYTE *b1, BYTE *b2, int len);

//打印显示Byte数组
void printByte(BYTE* b,int len);

//将16进制字符串转换为BYTE数组，注意length需要为偶数，转换后msg的长度为lenth/2
void HextoByte(BYTE *msg, BYTE *hex, int length);

//将unsigned int转为BYTE数组,hash长度固定为8位
void DwordtoByte(BYTE *out_hash, DWORD *hash);

//将BYTE数组转换为DWORD的BYTE串
void BytetoDwordbyte(BYTE *hash, BYTE *out_hash);

//把12次扩域元素转换为BYTE数组，得到大小为384字节大小的msg
void F12toByte(BYTE *msg, BNField12 b);

//将点P转换为64个字节串，注意P需为规范型
void PtoByte(BYTE *b, BNPoint P);

/*
  k：生成的共享密钥
  msg:输入消息的字节指针
  msglen:输入消息的字节长度
  klen : 需要获取的共享密钥的比特长度
*/
void KDF(BYTE *k, BYTE *msg, int msgLength, int klen);

/*
  h1：函数返回值
  msg:输入消息的字节指针
  len:输入消息的字节长度
  n : 通常为大整数N
*/
void Hash_1(CBigInt *h1, BYTE *msg, int len, CBigInt n);

//unsigned char 转 char
void convert_UnCharToStr(char* str, unsigned char* unChar, int ucLen);

//char 转 unsigned char
void convert_StrToUnChar(char* str, unsigned char* unChar, int cLen);

//uint8_t 转 BNPoint
void convert_unCharToBNPoint(uint8_t *c, BNPoint *R);

//uint8_t 转 BNPoint2
void convert_unCharToBNPoint2(uint8_t *c, BNPoint2 *R);

#endif /*UTILITY_H*/
